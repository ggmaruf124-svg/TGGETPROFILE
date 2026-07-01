import os
import sqlite3
import httpx
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# 🔑 JWT টোকেন কনফিগারেশন (আপনার সিক্রেটের মতো পরিবর্তন করতে পারেন)
SECRET_KEY = "SUPER_SECRET_KEY_FOR_FF_CHECKER"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # ১ দিন মেয়াদ

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

app = FastAPI(title="FF Premium Checker API with Credit System")

# 🌐 CORS পলিসি যুক্ত করা হয়েছে যাতে গিটহাব পেজ থেকে অ্যাক্সেস পাওয়া যায়
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "database.db"

# 🗄️ ডাটাবেস এবং টেবিল তৈরি করার ফাংশন
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # ইউজার টেবিল (ইউজারনেম, পাসওয়ার্ড এবং পয়েন্ট/ক্রেডিট রাখার জন্য)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            credits INTEGER DEFAULT 10
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# 📝 Pydantic স্কিমা (ডাটা ভ্যালিডেশনের জন্য)
class UserAuth(BaseModel):
    username: str
    password: str

# 🔒 পাসওয়ার্ড হ্যাশিং এবং টোকেন ইউটিলিটিজ
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 👤 বর্তমান লগইন থাকা ইউজারকে খুঁজে বের করার ডিপেন্ডেন্সি
async def get_current_user(token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user is None:
        raise credentials_exception
    return dict(user)

# 🔍 ইউআইডি ভ্যালিডেশন
def validate_uid(uid: str):
    if not uid or not uid.isdigit() or len(uid) < 5:
        raise HTTPException(status_code=400, detail="Invalid UID format.")
    return uid

# -------------------------------------------------------------------
# 🔐 অথরাইজেশন এন্ডপয়েন্টসমূহ (Registration & Login)
# -------------------------------------------------------------------

@app.post("/api/register")
async def register(user: UserAuth, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (user.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    # নতুন ইউজার খোলার সাথে সাথে সে ১০ পয়েন্ট/ক্রেডিট ফ্রি পাবে (ইচ্ছা হলে পরিবর্তন করতে পারেন)
    cursor.execute("INSERT INTO users (username, password, credits) VALUES (?, ?, ?)", (user.username, hashed_password, 10))
    db.commit()
    return {"status": "success", "message": "User registered successfully"}

@app.post("/api/login")
async def login(user: UserAuth, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (user.username,))
    db_user = cursor.fetchone()
    
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": db_user["username"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/user/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"], "credits": current_user["credits"]}

# -------------------------------------------------------------------
# 📊 ডাটা চেকার এন্ডপয়েন্টসমূহ (পয়েন্ট ডিডাকশন বা মাইনাস লজিকসহ)
# -------------------------------------------------------------------

# পয়েন্ট চেক এবং মাইনাস করার সাধারণ ফাংশন
def deduct_credit(user_id: int, current_credits: int, db: sqlite3.Connection):
    if current_credits <= 0:
        raise HTTPException(status_code=403, detail="Insufficient points! Please contact Admin.")
    
    new_credits = current_credits - 1
    cursor = db.cursor()
    cursor.execute("UPDATE users SET credits = ? WHERE id = ?", (new_credits, user_id))
    db.commit()

# ১. প্রোফাইল ইনফো 
@app.get("/api/checker/info")
async def get_profile_info(uid: str, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    validate_uid(uid)
    deduct_credit(current_user["id"], current_user["credits"], db)
    
    # ⚠️ আপনার আসল থার্ড-পার্টি ফ্রি ফায়ার এপিআই লিংক এখানে বসাবেন
    third_party_url = f"https://api.freefireapi.com/info?uid={uid}" 
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(third_party_url, timeout=15.0)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Third-party API error")
            return response.json()
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="External API unavailable")

# ২. প্রোফাইল কার্ড (ইমেজ ডাউনলোড)
@app.get("/api/checker/card")
async def get_profile_card(uid: str, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    validate_uid(uid)
    deduct_credit(current_user["id"], current_user["credits"], db)
    
    # ⚠️ প্রোফাইল কার্ডের জন্য আপনার ব্যবহৃত আসল ইমেজ জেনারেটর লিংকটি এখানে বসাবেন
    image_api_url = f"https://api.freefireapi.com/card?uid={uid}"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(image_api_url, timeout=20.0)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch profile card image")
            return StreamingResponse(response.iter_bytes(), media_type="image/png")
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Image generation server down")

# ৩. প্লেয়ার ড্রেস 
@app.get("/api/checker/dress")
async def get_player_dress(uid: str, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    validate_uid(uid)
    deduct_credit(current_user["id"], current_user["credits"], db)
    
    # ⚠️ প্লেয়ার ড্রেসের আসল সোর্স এপিআই ইউআরএলটি এখানে বসাবেন
    dress_api_url = f"https://api.freefireapi.com/dress?uid={uid}"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(dress_api_url, timeout=15.0)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch player dress data")
            return response.json()
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Dress checker API unavailable")

@app.get("/")
async def root():
    return {"status": "active", "message": "Premium Credit API System is Running!"}

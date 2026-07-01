import os
import time
import math
import asyncio
import sqlite3
import httpx
import bcrypt  
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, Request, HTTPException, Depends, status, Query
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
import jwt

SECRET_KEY = "SUPER_SECRET_MINIMALIST_KEY_CHANGE_THIS"
ALGORITHM = "HS256"
DB_FILE = "freefire_checker.db"

app = FastAPI(title="Premium FreeFire Profile Checker API")

# CORS Policy configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        credits INTEGER DEFAULT 100,
        is_premium BOOLEAN DEFAULT 0,
        last_search_timestamp REAL DEFAULT 0,
        search_count_minute INTEGER DEFAULT 0
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recharge_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        method TEXT NOT NULL,
        transaction_id TEXT UNIQUE NOT NULL,
        amount REAL NOT NULL,
        status TEXT DEFAULT 'Pending',
        timestamp REAL NOT NULL
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bkash_number TEXT DEFAULT '01700000000',
        nagad_number TEXT DEFAULT '01900000000'
    )""")
    cursor.execute("SELECT COUNT(*) FROM settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO settings (bkash_number, nagad_number) VALUES ('01700000000', '01900000000')")
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def generate_api_key():
    return os.urandom(24).hex()

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

def enforce_rate_and_credit(username: str, db: sqlite3.Connection, cost: int = 1):
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user["credits"] < cost:
        raise HTTPException(status_code=402, detail="Insufficient credits. Please recharge.")
    
    now = time.time()
    last_ts = user["last_search_timestamp"]
    count = user["search_count_minute"]
    is_prem = bool(user["is_premium"])
    
    window = 300 if is_prem else 60
    limit = 30 if is_prem else 5
    
    if now - last_ts > window:
        count = 0
        last_ts = now
    
    if count >= limit:
        retry_after = math.ceil(window - (now - last_ts))
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Try again in {retry_after}s.")
    
    new_count = count + 1
    new_credits = user["credits"] - cost
    cursor.execute("""
        UPDATE users 
        SET credits = ?, last_search_timestamp = ?, search_count_minute = ? 
        WHERE username = ?
    """, (new_credits, last_ts, new_count, username))
    db.commit()

def validate_uid(uid: str):
    if not uid.isdigit() or len(uid) < 6:
        raise HTTPException(status_code=400, detail="Invalid UID. Must be numerical and at least 6 digits.")

class AuthModel(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=4)

class RechargeModel(BaseModel):
    method: str
    transaction_id: str
    amount: float

class DecisionModel(BaseModel):
    request_id: int

class UpdateLimitModel(BaseModel):
    username: str
    credits: int
    is_premium: bool

class SettingsModel(BaseModel):
    bkash_number: str
    nagad_number: str

@app.post("/api/register")
def register(data: AuthModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    user = cursor.execute("SELECT id FROM users WHERE username = ?", (data.username,)).fetchone()
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    pwd_hash = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    api_key = generate_api_key()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)",
                       (data.username, pwd_hash, api_key))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Registration failed.")
    return {"message": "Registration successful. 100 free credits allocated."}

@app.post("/api/login")
def login(data: AuthModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (data.username,)).fetchone()
    
    if not user or not bcrypt.checkpw(data.password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = jwt.encode({"sub": user["username"], "exp": time.time() + 86400}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "username": user["username"]}

@app.get("/api/user/me")
def get_me(request: Request, db: sqlite3.Connection = Depends(get_db)):
    auth_hdr = request.headers.get("Authorization")
    if not auth_hdr or not auth_hdr.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authorized")
    token = auth_hdr.split(" ")[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Session expired/Invalid")
    
    user = db.execute("SELECT username, api_key, credits, is_premium FROM users WHERE username = ?", (username,)).fetchone()
    return dict(user)

@app.get("/api/checker/info")
async def get_profile_info(uid: str, request: Request, db: sqlite3.Connection = Depends(get_db)):
    auth_hdr = request.headers.get("Authorization")
    if not auth_hdr or not auth_hdr.startswith("Bearer "): raise HTTPException(status_code=401)
    username = verify_token(auth_hdr.split(" ")[1])
    if not username: raise HTTPException(status_code=401)
    
    validate_uid(uid)
    enforce_rate_and_credit(username, db)
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"http://raw.thug4ff.xyz/info?uid={uid}&key=great", timeout=10.0)
            return resp.json()
        except Exception:
            raise HTTPException(status_code=502, detail="External API error or timeout.")

@app.get("/api/checker/card")
async def get_profile_card(uid: str, request: Request, db: sqlite3.Connection = Depends(get_db)):
    auth_hdr = request.headers.get("Authorization")
    if not auth_hdr or not auth_hdr.startswith("Bearer "): raise HTTPException(status_code=401)
    username = verify_token(auth_hdr.split(" ")[1])
    if not username: raise HTTPException(status_code=401)
    
    validate_uid(uid)
    enforce_rate_and_credit(username, db)
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"https://profile.thug4ff.xyz/api/profile_card?uid={uid}", timeout=10.0)
            return Response(content=resp.content, media_type=resp.headers.get("content-type", "image/png"))
        except Exception:
            raise HTTPException(status_code=502, detail="Failed to proxy profile image card.")

@app.get("/api/checker/dress")
async def get_player_dress(uid: str, request: Request, db: sqlite3.Connection = Depends(get_db)):
    auth_hdr = request.headers.get("Authorization")
    if not auth_hdr or not auth_hdr.startswith("Bearer "): raise HTTPException(status_code=401)
    username = verify_token(auth_hdr.split(" ")[1])
    if not username: raise HTTPException(status_code=401)
    
    validate_uid(uid)
    enforce_rate_and_credit(username, db)
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"http://raw.thug4ff.xyz/info?uid={uid}&key=great", timeout=10.0)
            return resp.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Failed to fetch data from provider.")

@app.get("/api/v1/fetch_all")
async def developer_fetch_all(uid: str = Query(...), api_key: Optional[str] = Depends(API_KEY_HEADER), db: sqlite3.Connection = Depends(get_db)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key Missing")
    user = db.execute("SELECT username FROM users WHERE api_key = ?", (api_key,)).fetchone()
    if not user:
        raise HTTPException(status_code=403, detail="Invalid API Key Configuration")
    
    validate_uid(uid)
    enforce_rate_and_credit(user["username"], db, cost=1)
    
    async with httpx.AsyncClient() as client:
        tasks = [
            client.get(f"http://raw.thug4ff.xyz/info?uid={uid}&key=great", timeout=10.0),
            client.get(f"https://profile.thug4ff.xyz/api/profile_card?uid={uid}", timeout=10.0),
            client.get(f"http://raw.thug4ff.xyz/info?uid={uid}&key=great", timeout=10.0)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        info_res = results[0] if not isinstance(results[0], Exception) else None
        
        return {
            "uid": uid,
            "profile_info": info_res.json() if (info_res and info_res.status_code == 200) else "Error fetching data",
            "profile_card_url": f"https://profile.thug4ff.xyz/api/profile_card?uid={uid}",
            "player_dress_url": f"http://raw.thug4ff.xyz/info?uid={uid}&key=great"
        }

@app.post("/api/recharge/submit")
def submit_recharge(data: RechargeModel, request: Request, db: sqlite3.Connection = Depends(get_db)):
    auth_hdr = request.headers.get("Authorization")
    if not auth_hdr or not auth_hdr.startswith("Bearer "): raise HTTPException(status_code=401)
    username = verify_token(auth_hdr.split(" ")[1])
    if not username: raise HTTPException(status_code=401)
    
    cursor = db.cursor()
    try:
        cursor.execute("""
            INSERT INTO recharge_requests (username, method, transaction_id, amount, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (username, data.method, data.transaction_id, data.amount, time.time()))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Transaction ID already submitted.")
    return {"message": "Recharge request submitted successfully for verification."}

@app.get("/api/settings/get_numbers")
def get_numbers(db: sqlite3.Connection = Depends(get_db)):
    res = db.execute("SELECT bkash_number, nagad_number FROM settings WHERE id = 1").fetchone()
    return dict(res)

@app.get("/admin/stats")
def admin_stats(db: sqlite3.Connection = Depends(get_db)):
    total_users = db.execute("SELECT count(*) FROM users").fetchone()[0]
    pending_reqs = db.execute("SELECT count(*) FROM recharge_requests WHERE status = 'Pending'").fetchone()[0]
    total_processed = db.execute("SELECT count(*) FROM recharge_requests WHERE status != 'Pending'").fetchone()[0]
    return {
        "total_users": total_users,
        "pending_requests": pending_reqs,
        "processed_requests": total_processed,
        "system_load": "Optimal"
    }

@app.get("/admin/requests")
def admin_get_requests(db: sqlite3.Connection = Depends(get_db)):
    reqs = db.execute("SELECT * FROM recharge_requests ORDER BY id DESC").fetchall()
    return [dict(r) for r in reqs]

@app.post("/admin/requests/approve")
def admin_approve(data: DecisionModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    req = cursor.execute("SELECT * FROM recharge_requests WHERE id = ?", (data.request_id,)).fetchone()
    if not req or req["status"] != "Pending":
        raise HTTPException(status_code=400, detail="Invalid request processing context.")
    
    awarded_credits = int(req["amount"] * 2) 
    
    cursor.execute("UPDATE recharge_requests SET status = 'Approved' WHERE id = ?", (data.request_id,))
    cursor.execute("UPDATE users SET credits = credits + ?, is_premium = 1 WHERE username = ?", (awarded_credits, req["username"]))
    db.commit()
    return {"message": "Request approved. User upgraded to Premium."}

@app.post("/admin/requests/reject")
def admin_reject(data: DecisionModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    req = cursor.execute("SELECT id FROM recharge_requests WHERE id = ?", (data.request_id,)).fetchone()
    if not req: raise HTTPException(status_code=404)
    cursor.execute("UPDATE recharge_requests SET status = 'Rejected' WHERE id = ?", (data.request_id,))
    db.commit()
    return {"message": "Request declined successfully."}

@app.get("/admin/users")
def admin_get_users(db: sqlite3.Connection = Depends(get_db)):
    users = db.execute("SELECT username, credits, is_premium FROM users").fetchall()
    return [dict(u) for u in users]

@app.post("/admin/users/update_limits")
def admin_update_limits(data: UpdateLimitModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("UPDATE users SET credits = ?, is_premium = ? WHERE username = ?", (data.credits, 1 if data.is_premium else 0, data.username))
    db.commit()
    return {"message": "User metrics parameters modified successfully."}

@app.post("/admin/settings/update_numbers")
def admin_update_numbers(data: SettingsModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("UPDATE settings SET bkash_number = ?, nagad_number = ? WHERE id = 1", (data.bkash_number, data.nagad_number))
    db.commit()
    return {"message": "Gateway configuration synchronized."}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

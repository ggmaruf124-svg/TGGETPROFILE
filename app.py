import os
import httpx
import sqlite3
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

app = FastAPI(title="FF Profile Checker API")

# 🌐 CORS Middleware যুক্ত করা হয়েছে যেন গিটহাব পেজ থেকে রিকোয়েস্ট ব্লক না হয়
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # আপনার গিটহাব পেজের লিংকও এখানে দিতে পারেন
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 💾 ডেটাবেস কানেকশন (যদি আপনার প্রজেক্টে ডেটা ট্র্যাকিং বা লগিং থাকে)
DB_PATH = "database.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# 🔍 ইউআইডি ভ্যালিডেশন ফাংশন
def validate_uid(uid: str):
    if not uid or not uid.isdigit() or len(uid) < 5:
        raise HTTPException(status_code=400, detail="Invalid UID format. Must be numbers only.")
    return uid

# -------------------------------------------------------------------
# 🔓 এন্ডপয়েন্টসমূহ (লগইন/টোকেন সিকিউরিটি সম্পূর্ণ মুক্ত)
# -------------------------------------------------------------------

# ১. প্রোফাইল ইনফো এন্ডপয়েন্ট (টেক্সট/JSON ডেটা)
@app.get("/api/checker/info")
async def get_profile_info(uid: str, db: sqlite3.Connection = Depends(get_db)):
    validate_uid(uid)
    
    # ⚠️ আপনার আসল থার্ড-পার্টি এপিআই ইউআরএল এবং কি (Key) এখানে বসাবেন
    third_party_url = f"https://api.freefireapi.com/info?uid={uid}" 
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(third_party_url, timeout=15.0)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Third-party API error")
            return response.json()
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="External API unavailable")


# ২. প্রোফাইল কার্ড এন্ডপয়েন্ট (ইমেজ রেসপন্স)
@app.get("/api/checker/card")
async def get_profile_card(uid: str, db: sqlite3.Connection = Depends(get_db)):
    validate_uid(uid)
    
    # ⚠️ প্রোফাইল কার্ডের জন্য আপনার ব্যবহৃত আসল ইমেজ জেনারেটর লিংকটি এখানে বসাবেন
    image_api_url = f"https://api.freefireapi.com/card?uid={uid}"
    
    async with httpx.AsyncClient() as client:
        try:
            # ইমেজ ডাউনলোড করার জন্য রিকোয়েস্ট পাঠানো হচ্ছে
            response = await client.get(image_api_url, timeout=20.0)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch profile card image")
            
            # ফ্রন্টএন্ডে সরাসরি ইমেজ ফাইল (Blob) হিসেবে রিটার্ন করা হচ্ছে
            return StreamingResponse(response.iter_bytes(), media_type="image/png")
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Image generation server down")


# ৩. প্লেয়ার ড্রেস এন্ডপয়েন্ট (টেক্সট/JSON ডেটা)
@app.get("/api/checker/dress")
async def get_player_dress(uid: str, db: sqlite3.Connection = Depends(get_db)):
    validate_uid(uid)
    
    # ⚠️ প্লেয়ার ড্রেসের আসল সোর্স এপিআই ইউআরএলটি এখানে বসাবেন
    dress_api_url = f"https://api.freefireapi.com/dress?uid={uid}"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(dress_api_url, timeout=15.0)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch player dress data")
            
            # যেহেতু এটি ইমেজ দেয় না, তাই ফ্রন্টএন্ডের জন্য JSON রিটার্ন করা হচ্ছে
            return response.json()
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Dress checker API unavailable")


# 🛠️ সার্ভার রুট চেকার
@app.get("/")
async def root():
    return {"status": "success", "message": "FF Checker Backend is running successfully!"}

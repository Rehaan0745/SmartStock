# main.py
# FastAPI Smart Home Inventory - Render-ready, env-driven, asyncpg, JWT auth, bcrypt
import os
from datetime import datetime, timedelta
from typing import Optional

import jwt
import bcrypt
import asyncpg
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# ------------------------
# Load env
# ------------------------
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "inventory_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "password")

JWT_SECRET = os.getenv("JWT_SECRET", "change_this_super_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRES_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "120"))

# ------------------------
# App init
# ------------------------
app = FastAPI(title="Smart Home Inventory API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace with your frontend origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ------------------------
# Pydantic models
# ------------------------
class RegisterPayload(BaseModel):
    username: str
    password: str
    email: str

class LoginPayload(BaseModel):
    username: str
    password: str

class InventoryPayload(BaseModel):
    item_name: str
    dsc: Optional[str] = None
    category: Optional[str] = None
    qty: Optional[int] = 0
    unit: Optional[str] = None
    exp_date: Optional[str] = None  # ISO date "YYYY-MM-DD"
    price: Optional[float] = 0.0

# ------------------------
# Startup / shutdown: DB pool
# ------------------------
@app.on_event("startup")
async def startup():
    app.state.db = await asyncpg.create_pool(
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        host=DB_HOST,
        port=DB_PORT,
        min_size=1,
        max_size=10,
    )

@app.on_event("shutdown")
async def shutdown():
    await app.state.db.close()

# ------------------------
# Utility: users & auth
# ------------------------
async def get_user_by_username(username: str):
    query = "SELECT * FROM users WHERE username = $1"
    async with app.state.db.acquire() as conn:
        return await conn.fetchrow(query, username)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRES_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        user = await get_user_by_username(username)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# ------------------------
# Routes: status, register, login
# ------------------------
@app.get("/api/status")
async def status():
    return {"status": "ok"}

@app.post("/register")
async def register(payload: RegisterPayload):
    # Basic validation done by Pydantic
    existing = await get_user_by_username(payload.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = bcrypt.hashpw(payload.password.encode(), bcrypt.gensalt()).decode()
    query = """
        INSERT INTO users (username, password_hash, email, account_type, created_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, username, email, account_type
    """
    async with app.state.db.acquire() as conn:
        user = await conn.fetchrow(query,
                                   payload.username,
                                   hashed_pw,
                                   payload.email,
                                   "Client",  # default account type matching your enum
                                   datetime.utcnow())
    return {"msg": "registered", "user": dict(user) if user else None}

@app.post("/login")
async def login(payload: LoginPayload):
    user = await get_user_by_username(payload.username)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    stored_hash = user["password_hash"]
    if not bcrypt.checkpw(payload.password.encode(), stored_hash.encode()):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer", "user_id": user["id"], "username": user["username"]}

# ------------------------
# Inventory endpoints (user-scoped)
# ------------------------
@app.get("/inventory")
async def list_inventory(current_user=Depends(get_current_user)):
    q = "SELECT * FROM inventory WHERE user_id = $1 ORDER BY date_added DESC"
    async with app.state.db.acquire() as conn:
        rows = await conn.fetch(q, current_user["id"])
    return [dict(r) for r in rows]

@app.post("/inventory")
async def add_inventory(item: InventoryPayload, current_user=Depends(get_current_user)):
    q = """
        INSERT INTO inventory (user_id, item_name, dsc, category, qty, unit, exp_date, price)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        RETURNING id
    """
    # convert exp_date to date if provided (asyncpg will accept ISO string for DATE)
    async with app.state.db.acquire() as conn:
        row = await conn.fetchrow(q,
                                  current_user["id"],
                                  item.item_name,
                                  item.dsc,
                                  item.category,
                                  item.qty,
                                  item.unit,
                                  item.exp_date,
                                  item.price)
    return {"msg": "item_added", "item_id": row["id"] if row else None}

@app.delete("/inventory/{item_id}")
async def delete_inventory(item_id: int, current_user=Depends(get_current_user)):
    q = "DELETE FROM inventory WHERE id = $1 AND user_id = $2"
    async with app.state.db.acquire() as conn:
        res = await conn.execute(q, item_id, current_user["id"])
    if res == "DELETE 0":
        raise HTTPException(status_code=404, detail="Not found or not your item")
    return {"msg": "deleted"}

# ------------------------
# Optional: expiry alerts helper
# ------------------------
@app.get("/alerts/near-expiry")
async def near_expiry(days: int = 3, current_user=Depends(get_current_user)):
    # returns inventory items whose exp_date is within `days` from today
    q = "SELECT * FROM inventory WHERE user_id=$1 AND exp_date IS NOT NULL AND exp_date <= (CURRENT_DATE + $2::int)"
    async with app.state.db.acquire() as conn:
        rows = await conn.fetch(q, current_user["id"], days)
    return [dict(r) for r in rows]

# ------------------------
# Run (local / Render)
# ------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "5000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)

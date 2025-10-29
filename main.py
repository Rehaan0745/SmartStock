# main.py
# SmartStock API — JWT access+refresh, per-user inventory, update & delete endpoints,
# analytics including near-expiry, env-configured for Render deployment.

import os
import logging
from datetime import datetime, timedelta
from typing import Dict

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from argon2 import PasswordHasher
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt  # PyJWT

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smartstock")

# -----------------------
# Environment variables (defaults provided for instant deploy)
# -----------------------
DB_HOST = os.getenv("DB_HOST", "dpg-d3sd3e6r433s73cooo4g-a.singapore-postgres.render.com")
DB_NAME = os.getenv("DB_NAME", "smart_inventory_f8ui")
DB_USER = os.getenv("DB_USER", "rehaan")
DB_PASS = os.getenv("DB_PASS", "ZnG4OPK2pNo3NOfgfOTPyRjzD6KzWW6r")
DB_SSL = os.getenv("DB_SSL", "require")

JWT_SECRET = os.getenv("JWT_SECRET", "change_this_super_secret_key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRES_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "15"))
REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "7"))

# -----------------------
# App + CORS
# -----------------------
app = FastAPI(title="SmartStock API (per-user inventory)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace with specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# DB helper
# -----------------------
def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        cursor_factory=RealDictCursor,
        sslmode=DB_SSL
    )

# -----------------------
# JWT utilities
# -----------------------
security = HTTPBearer()

def make_token(payload: Dict, expires: timedelta, token_type: str):
    data = payload.copy()
    data.update({"exp": datetime.utcnow() + expires, "type": token_type})
    token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT returns str in v2.x
    return token

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_access_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication scheme")
    payload = decode_token(creds.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload

# -----------------------
# Models
# -----------------------
ph = PasswordHasher()

class Register(BaseModel):
    username: str
    email: str
    password: str

class Login(BaseModel):
    username: str
    password: str

class InventoryItem(BaseModel):
    pname: str
    qty: int
    price: float
    expiry: str = None
    category: str
    used_value: float = 0.0

class RefreshRequest(BaseModel):
    refresh_token: str

# -----------------------
# Optional static frontend mount
# -----------------------
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    logger.info("Mounted frontend from %s", frontend_dir)
else:
    logger.info("No frontend folder found; API-only mode.")

# -----------------------
# Auth endpoints
# -----------------------
@app.post("/register")
def register(user: Register):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (user.username, user.email))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Username or email already exists.")
        hashed_pw = ph.hash(user.password)
        cur.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (%s,%s,%s,%s) RETURNING id",
            (user.username, user.email, hashed_pw, datetime.utcnow())
        )
        inserted = cur.fetchone()
        conn.commit()
        return {"message": "Registration successful", "user_id": inserted["id"] if inserted else None}
    except Exception as e:
        conn.rollback()
        logger.exception("Registration error")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.post("/login")
def login(user: Login):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users WHERE username=%s", (user.username,))
        existing = cur.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")
        try:
            ph.verify(existing["password_hash"], user.password)
        except Exception:
            raise HTTPException(status_code=401, detail="Incorrect password")
        payload = {"sub": str(existing["id"]), "username": existing["username"]}
        access = make_token(payload, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
        refresh = make_token(payload, timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS), "refresh")
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "user_id": existing["id"],
            "username": existing["username"],
            "expires_in_minutes": ACCESS_TOKEN_EXPIRES_MINUTES
        }
    finally:
        cur.close()
        conn.close()

@app.post("/refresh")
def refresh(req: RefreshRequest):
    try:
        payload = jwt.decode(req.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    new_access = make_token({"sub": payload.get("sub"), "username": payload.get("username")}, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
    return {"access_token": new_access, "token_type": "bearer", "expires_in_minutes": ACCESS_TOKEN_EXPIRES_MINUTES}

# -----------------------
# Inventory endpoints (per-user) — protected
# -----------------------
@app.post("/add_item/{user_id}")
def add_item(user_id: int, item: InventoryItem, token_payload: dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to target user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO inventory (user_id, pname, qty, price, expiry, category, used_value)
            VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id
        """, (user_id, item.pname, item.qty, item.price, item.expiry, item.category, item.used_value))
        inserted = cur.fetchone()
        conn.commit()
        return {"message": "Item added successfully", "item_id": inserted["id"] if inserted else None}
    except Exception as e:
        conn.rollback()
        logger.exception("Add item error")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.put("/update_item/{user_id}/{item_id}")
def update_item(user_id: int, item_id: int, updates: InventoryItem, token_payload: dict = Depends(require_access_token)):
    # ensure token user matches path user_id
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to target user")
    conn = get_db()
    cur = conn.cursor()
    try:
        # Only update item that belongs to this user
        cur.execute("""
            UPDATE inventory
            SET pname=%s, qty=%s, price=%s, expiry=%s, category=%s, used_value=%s
            WHERE id=%s AND user_id=%s
            RETURNING id
        """, (updates.pname, updates.qty, updates.price, updates.expiry, updates.category, updates.used_value, item_id, user_id))
        updated = cur.fetchone()
        if not updated:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Item not found or not owned by user")
        conn.commit()
        return {"message": "Item updated successfully", "item_id": updated["id"]}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Update error")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.delete("/delete_item/{user_id}/{item_id}")
def delete_item(user_id: int, item_id: int, token_payload: dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to target user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM inventory WHERE id=%s AND user_id=%s RETURNING id", (item_id, user_id))
        deleted = cur.fetchone()
        if not deleted:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Item not found or not owned by user")
        conn.commit()
        return {"message": "Item deleted"}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Delete error")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.get("/inventory/{user_id}")
def get_inventory(user_id: int, token_payload: dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to requested user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM inventory WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
        items = cur.fetchall()
        today = datetime.utcnow().date()
        near_expiry = []
        for i in items:
            exp = i.get("expiry")
            if exp:
                try:
                    d = datetime.strptime(str(exp), "%Y-%m-%d").date()
                    if (d - today).days <= 3:
                        near_expiry.append(i)
                except Exception:
                    # ignore parse errors
                    pass
        # low_stock heuristic
        low_stock = [i for i in items if (i.get("qty") or 0) <= 0.25 * ((i.get("qty") or 0) + (i.get("used_value") or 0))]

        total_value = sum((i.get("price") or 0) * (i.get("qty") or 0) for i in items)
        used_value = sum(i.get("used_value") or 0 for i in items)
        saved_value = round(total_value - used_value, 2)

        categories = {}
        for i in items:
            categories.setdefault(i.get("category") or "Uncategorized", []).append(i)

        analytics = {
            "total_items": len(items),
            "near_expiry": len(near_expiry),
            "low_stock": len(low_stock),
            "saved_value": saved_value,
        }

        return {"items": items, "analytics": analytics, "categories": categories}
    except Exception as e:
        logger.exception("Fetch inventory failed")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()
@app.get("/alerts")
async def get_near_expiry_alerts(current_user: dict = Depends(get_current_user)):
    query = """
        SELECT pname, expiry, (expiry - CURRENT_DATE) AS days_left
        FROM near_expiry_alerts
        WHERE username = :username
        ORDER BY expiry ASC;
    """
    return await database.fetch_all(query, values={"username": current_user["username"]})


# -----------------------
# Health route
# -----------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -----------------------
# Deterministic requirements.txt
# -----------------------
REQUIREMENTS = [
    "fastapi>=0.95.0",
    "uvicorn[standard]>=0.22.0",
    "psycopg2-binary>=2.9.6",
    "argon2-cffi>=21.3.0",
    "pydantic>=1.10.7",
    "PyJWT>=2.8.0"
]

if __name__ == "__main__":
    try:
        with open("requirements.txt", "w") as f:
            f.write("\n".join(REQUIREMENTS) + "\n")
        logger.info("requirements.txt generated.")
    except Exception:
        logger.exception("Failed to write requirements.txt")
    import uvicorn as _uvicorn
    port = int(os.getenv("PORT", 8000))
    _uvicorn.run("main:app", host="0.0.0.0", port=port, workers=1)

pip install -r requirements.txt

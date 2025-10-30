# main.py — SmartStock Render-ready FastAPI backend (PART 1/2)

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt  # PyJWT
from fastapi.staticfiles import StaticFiles
# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("smartstock")

# -----------------------
# Helpers
# -----------------------
def parse_int_expr(value: Optional[str], default: int) -> int:
    if not value:
        return default
    try:
        if "*" in value:
            parts = [int(x.strip()) for x in value.split("*") if x.strip()]
            prod = 1
            for p in parts:
                prod *= p
            return prod
        return int(value.strip())
    except Exception:
        logger.warning("Failed to parse int expression '%s', using default %s", value, default)
        return default

def parse_cors_origins(value: Optional[str]):
    if not value:
        return ["*"]
    value = value.strip()
    if value == "*":
        return ["*"]
    return [u.strip() for u in value.split(",") if u.strip()]

# -----------------------
# Environment / Defaults
# -----------------------
DB_HOST = os.getenv("DB_HOST", "dpg-d3sd3e6r433s73cooo4g-a.singapore-postgres.render.com")
DB_NAME = os.getenv("DB_NAME", "smart_inventory_f8ui")
DB_USER = os.getenv("DB_USER", "rehaan")
DB_PASS = os.getenv("DB_PASS", "ZnG4OPK2pNo3NOfgfOTPyRjzD6KzWW6r")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_SSLMODE = os.getenv("DB_SSL", "require")  # "require" or "disable"

JWT_SECRET = os.getenv("JWT_SECRET", "change_this_super_secret_key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRES_MINUTES = parse_int_expr(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES"), 60)
REFRESH_TOKEN_EXPIRES_DAYS = parse_int_expr(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS"), 7)

CORS_ORIGINS = parse_cors_origins(
    os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5500,http://127.0.0.1:5500,https://smartstock-qre1.onrender.com",
    )
)

if JWT_SECRET == "change_this_super_secret_key":
    logger.warning("Using default JWT_SECRET. Set JWT_SECRET env var in production!")

logger.info("Config: ACCESS_TOKEN_EXPIRES_MINUTES=%s REFRESH_TOKEN_EXPIRES_DAYS=%s CORS_ORIGINS=%s",
            ACCESS_TOKEN_EXPIRES_MINUTES, REFRESH_TOKEN_EXPIRES_DAYS, CORS_ORIGINS)

# -----------------------
# FastAPI app + CORS
# -----------------------
app = FastAPI(title="SmartStock API")

# If allow_origins contains "*", allow_credentials should be False for browsers; keep True for explicit origins
allow_credentials_flag = True
if CORS_ORIGINS == ["*"]:
    logger.warning("CORS origins set to '*'; disabling credentials to comply with browsers.")
    allow_credentials_flag = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=allow_credentials_flag,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
ph = PasswordHasher()

# -----------------------
# DB helper (psycopg2)
# -----------------------
def get_db():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT,
            sslmode=DB_SSLMODE,
            cursor_factory=RealDictCursor,
        )
        return conn
    except Exception:
        logger.exception("Database connection failed")
        raise HTTPException(status_code=500, detail="Database connection failed")

# -----------------------
# JWT helpers
# -----------------------
def create_token(payload: Dict[str, Any], expires_delta: timedelta, token_type: str) -> str:
    to_encode = payload.copy()
    to_encode.update({"exp": int((datetime.utcnow() + expires_delta).timestamp()), "type": token_type})
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT v2 returns str; if bytes, decode
    if isinstance(token, bytes):
        token = token.decode()
    return token

def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")

def require_access_token(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    if not creds or creds.scheme.lower() != "bearer":
        logger.warning("Invalid auth scheme provided")
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(creds.credentials)
    if payload.get("type") != "access":
        logger.warning("Token type is not access: %s", payload.get("type"))
        raise HTTPException(status_code=401, detail="Invalid token type")
    logger.info("Access granted for sub=%s", payload.get("sub"))
    return payload

# -----------------------
# Pydantic models
# -----------------------
class Register(BaseModel):
    username: str
    email: str
    password: str

class Login(BaseModel):
    username: str
    password: str

class InventoryItemIn(BaseModel):
    item_name: str
    dsc: Optional[str] = None
    category: Optional[str] = None
    qty: int = Field(..., ge=0)
    unit: Optional[str] = None
    exp_date: Optional[str] = None  # "YYYY-MM-DD"
    price: float = Field(..., ge=0.0)

class RefreshIn(BaseModel):
    refresh_token: str

class ExpiryAlertIn(BaseModel):
    msg: str

# -----------------------
# Static frontend (optional)
# -----------------------
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    # Mount under /frontend to avoid masking API root
    app.mount("/frontend", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    logger.info("Mounted frontend directory at /frontend")
else:
    logger.info("No frontend directory found; API-only mode.")
    # main.py — SmartStock Render-ready FastAPI backend (PART 2/2)
# (This continues directly from the last line of Part 1 — no new imports)

# -----------------------
# Auth endpoints
# -----------------------

@app.post("/register")
def register(data: Register):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (data.username, data.email))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Username or email already exists")

        hashed_pw = ph.hash(data.password)
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (data.username, data.email, hashed_pw),
        )
        user_id = cur.fetchone()["id"]
        conn.commit()

        payload = {"sub": data.username, "user_id": user_id}
        access_token = create_token(payload, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
        refresh_token = create_token(payload, timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS), "refresh")
        return {"message": "Registration successful", "access_token": access_token, "refresh_token": refresh_token}

    except Exception as e:
        logger.exception("Registration failed: %s", e)
        raise HTTPException(status_code=500, detail="Registration failed")
    finally:
        cur.close()
        conn.close()


@app.post("/login")
def login(data: Login):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, password_hash FROM users WHERE username=%s", (data.username,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        try:
            ph.verify(user["password_hash"], data.password)
        except VerifyMismatchError:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        payload = {"sub": data.username, "user_id": user["id"]}
        access_token = create_token(payload, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
        refresh_token = create_token(payload, timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS), "refresh")
        return {"access_token": access_token, "refresh_token": refresh_token}

    except Exception as e:
        logger.exception("Login failed: %s", e)
        raise HTTPException(status_code=500, detail="Login failed")
    finally:
        cur.close()
        conn.close()


@app.post("/refresh")
def refresh(data: RefreshIn):
    payload = decode_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    new_payload = {"sub": payload["sub"], "user_id": payload["user_id"]}
    access_token = create_token(new_payload, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
    refresh_token = create_token(new_payload, timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS), "refresh")
    return {"access_token": access_token, "refresh_token": refresh_token}


# -----------------------
# Inventory endpoints
# -----------------------

@app.get("/inventory")
def get_inventory(payload: Dict[str, Any] = Depends(require_access_token)):
    user_id = payload["user_id"]
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM inventory WHERE user_id=%s ORDER BY id DESC", (user_id,))
        items = cur.fetchall()
        return items
    finally:
        cur.close()
        conn.close()


@app.post("/add_item/{user_id}")
def add_item(user_id: int, item: InventoryItemIn, payload: Dict[str, Any] = Depends(require_access_token)):
    if user_id != payload["user_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO inventory (user_id, item_name, dsc, category, qty, unit, exp_date, price)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
            """,
            (user_id, item.item_name, item.dsc, item.category, item.qty, item.unit, item.exp_date, item.price),
        )
        conn.commit()
        new_id = cur.fetchone()["id"]
        return {"message": "Item added", "id": new_id}
    finally:
        cur.close()
        conn.close()


@app.put("/update_item/{user_id}/{item_id}")
def update_item(user_id: int, item_id: int, item: InventoryItemIn, payload: Dict[str, Any] = Depends(require_access_token)):
    if user_id != payload["user_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE inventory SET item_name=%s, dsc=%s, category=%s, qty=%s, unit=%s, exp_date=%s, price=%s
            WHERE id=%s AND user_id=%s
            """,
            (item.item_name, item.dsc, item.category, item.qty, item.unit, item.exp_date, item.price, item_id, user_id),
        )
        conn.commit()
        return {"message": "Item updated"}
    finally:
        cur.close()
        conn.close()


@app.delete("/delete_item/{user_id}/{item_id}")
def delete_item(user_id: int, item_id: int, payload: Dict[str, Any] = Depends(require_access_token)):
    if user_id != payload["user_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM inventory WHERE id=%s AND user_id=%s", (item_id, user_id))
        conn.commit()
        return {"message": "Item deleted"}
    finally:
        cur.close()
        conn.close()


# -----------------------
# Expiry alert endpoints
# -----------------------

@app.post("/alerts/{user_id}/{inventory_id}")
def create_alert(user_id: int, inventory_id: int, data: ExpiryAlertIn, payload: Dict[str, Any] = Depends(require_access_token)):
    if user_id != payload["user_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO alerts (user_id, inventory_id, msg, created_at) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)",
            (user_id, inventory_id, data.msg),
        )
        conn.commit()
        return {"message": "Alert created"}
    finally:
        cur.close()
        conn.close()


@app.get("/alerts/{user_id}")
def get_alerts(user_id: int, payload: Dict[str, Any] = Depends(require_access_token)):
    if user_id != payload["user_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT a.id, a.msg, a.created_at, i.item_name
            FROM alerts a
            JOIN inventory i ON a.inventory_id = i.id
            WHERE a.user_id=%s
            ORDER BY a.created_at DESC
            """,
            (user_id,),
        )
        alerts = cur.fetchall()
        return alerts
    finally:
        cur.close()
        conn.close()


# -----------------------
# Utility / Health endpoints
# -----------------------

@app.get("/verify")
def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    return decode_token(creds.credentials)

@app.get("/health")
def health_check():
    return {"status": "ok"}

# -----------------------
# Global error handler
# -----------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# -----------------------
# Local run
# -----------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    logger.info("Starting SmartStock API on port %s", port)
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)


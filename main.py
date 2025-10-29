# main.py
# SmartStock — updated FastAPI backend with improved env parsing, CORS, and token debug helpers

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Depends, Request
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
# Helpers
# -----------------------
def parse_int_expr(value: Optional[str], default: int) -> int:
    """
    Parse environment integer-like strings. Accept plain integers or a simple product like "60*24".
    Falls back to default on parse errors.
    """
    if value is None:
        return default
    value = value.strip()
    try:
        if '*' in value:
            parts = [int(p.strip()) for p in value.split('*') if p.strip()]
            prod = 1
            for p in parts:
                prod *= p
            return prod
        return int(value)
    except Exception:
        logger.warning("Failed to parse int-like value '%s', using default %s", value, default)
        return default

def parse_cors_origins(value: Optional[str]):
    """
    Accept a single origin or a comma-separated list
    """
    if not value:
        return ["*"]
    value = value.strip()
    if value == "*":
        return ["*"]
    return [o.strip() for o in value.split(",") if o.strip()]

# -----------------------
# Env / defaults (override via environment)
# -----------------------
DB_HOST = os.getenv("DB_HOST", "dpg-d3sd3e6r433s73cooo4g-a.singapore-postgres.render.com")
DB_NAME = os.getenv("DB_NAME", "smart_inventory_f8ui")
DB_USER = os.getenv("DB_USER", "rehaan")
DB_PASS = os.getenv("DB_PASS", "ZnG4OPK2pNo3NOfgfOTPyRjzD6KzWW6r")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_SSLMODE = os.getenv("DB_SSL", "require")  # "require" or "disable"

JWT_SECRET = os.getenv("JWT_SECRET", "change_this_super_secret_key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRES_MINUTES = parse_int_expr(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", None), 60)
REFRESH_TOKEN_EXPIRES_DAYS = parse_int_expr(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", None), 7)

CORS_ORIGINS = parse_cors_origins(os.getenv("CORS_ORIGINS", "*"))

logger.info("Configuration: ACCESS_TOKEN_EXPIRES_MINUTES=%s REFRESH_TOKEN_EXPIRES_DAYS=%s CORS_ORIGINS=%s",
            ACCESS_TOKEN_EXPIRES_MINUTES, REFRESH_TOKEN_EXPIRES_DAYS, CORS_ORIGINS)

# -----------------------
# FastAPI app + CORS
# -----------------------
app = FastAPI(title="SmartStock API (final)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# DB helper (sync psycopg2)
# -----------------------
def get_db():
    # Build dsn; return connection or raise
    dsn = {
        "host": DB_HOST,
        "database": DB_NAME,
        "user": DB_USER,
        "password": DB_PASS,
        "cursor_factory": RealDictCursor,
    }
    # include port and sslmode when present
    if DB_PORT:
        dsn["port"] = DB_PORT
    if DB_SSLMODE:
        dsn["sslmode"] = DB_SSLMODE
    try:
        return psycopg2.connect(**dsn)
    except Exception as e:
        logger.exception("Database connection failed")
        raise HTTPException(status_code=500, detail="Database connection failed")

# -----------------------
# Auth / JWT helpers
# -----------------------
security = HTTPBearer()
ph = PasswordHasher()

def create_token(payload: Dict, expires_delta: timedelta, token_type: str) -> str:
    to_encode = payload.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta, "type": token_type})
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str) -> Dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        logger.exception("Invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")

def require_access_token(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    logger.debug("require_access_token called, creds present: %s", bool(creds))
    if not creds or creds.scheme.lower() != "bearer":
        logger.warning("Invalid auth scheme: %s", creds)
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        logger.debug("Decoding token, length: %d", len(creds.credentials or ""))
        payload = decode_token(creds.credentials)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected token decode error")
        raise HTTPException(status_code=401, detail="Not authenticated")
    if payload.get("type") != "access":
        logger.warning("Invalid token type: %s", payload.get("type"))
        raise HTTPException(status_code=401, detail="Invalid token type")
    logger.info("Token accepted for sub=%s", payload.get("sub"))
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
    qty: int
    unit: Optional[str] = None
    exp_date: Optional[str] = None  # "YYYY-MM-DD"
    price: float

class RefreshIn(BaseModel):
    refresh_token: str

class ExpiryAlertIn(BaseModel):
    msg: str

# -----------------------
# Static frontend mount (optional)
# -----------------------
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    logger.info("Mounted frontend from: %s", frontend_dir)
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
            raise HTTPException(status_code=400, detail="Username or Email already exists")
        hashed = ph.hash(user.password)
        cur.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (%s,%s,%s,%s) RETURNING id",
            (user.username, user.email, hashed, datetime.utcnow())
        )
        new = cur.fetchone()
        conn.commit()
        return {"message": "Registration successful", "user_id": new["id"] if new else None}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        logger.exception("Registration failed")
        raise HTTPException(status_code=500, detail="Registration failed")
    finally:
        cur.close()
        conn.close()

@app.post("/login")
def login(credentials: Login):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, username, password_hash FROM users WHERE username=%s", (credentials.username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        try:
            ph.verify(row["password_hash"], credentials.password)
        except Exception:
            raise HTTPException(status_code=401, detail="Incorrect password")
        payload = {"sub": str(row["id"]), "username": row["username"]}
        access = create_token(payload, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
        refresh = create_token(payload, timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS), "refresh")
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "user_id": row["id"],
            "username": row["username"],
            "expires_in_minutes": ACCESS_TOKEN_EXPIRES_MINUTES
        }
    finally:
        cur.close()
        conn.close()

@app.post("/refresh")
def refresh(req: RefreshIn):
    try:
        payload = jwt.decode(req.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    new_access = create_token({"sub": payload.get("sub"), "username": payload.get("username")}, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
    return {"access_token": new_access, "token_type": "bearer", "expires_in_minutes": ACCESS_TOKEN_EXPIRES_MINUTES}

# -----------------------
# Inventory endpoints
# -----------------------
@app.get("/inventory")
def get_inventory(token_payload: Dict = Depends(require_access_token)):
    user_id = token_payload.get("sub")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, user_id, item_name, dsc, category, qty, unit, date_added, exp_date, price
            FROM inventory WHERE user_id = %s ORDER BY date_added DESC
        """, (user_id,))
        items = cur.fetchall()
        # return both keys for frontend compatibility
        return {"items": items, "inventory": items}
    except Exception as e:
        logger.exception("Fetch inventory failed")
        raise HTTPException(status_code=500, detail="Fetch inventory failed")
    finally:
        cur.close()
        conn.close()

@app.get("/inventory/{user_id}")
def get_inventory_by_user(user_id: int, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to requested user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, user_id, item_name, dsc, category, qty, unit, date_added, exp_date, price
            FROM inventory WHERE user_id = %s ORDER BY date_added DESC
        """, (user_id,))
        items = cur.fetchall()
        return {"items": items, "inventory": items}
    except Exception as e:
        logger.exception("Fetch inventory by user failed")
        raise HTTPException(status_code=500, detail="Fetch inventory failed")
    finally:
        cur.close()
        conn.close()

@app.post("/add_item/{user_id}")
def add_item(user_id: int, item: InventoryItemIn, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to target user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO inventory (user_id, item_name, dsc, category, qty, unit, exp_date, price)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
        """, (user_id, item.item_name, item.dsc, item.category, item.qty, item.unit, item.exp_date, item.price))
        new = cur.fetchone()
        conn.commit()
        return {"message": "Item added", "item_id": new["id"] if new else None}
    except Exception as e:
        conn.rollback()
        logger.exception("Add item failed")
        raise HTTPException(status_code=500, detail="Add item failed")
    finally:
        cur.close()
        conn.close()

@app.put("/update_item/{user_id}/{item_id}")
def update_item(user_id: int, item_id: int, updates: InventoryItemIn, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE inventory SET item_name=%s, dsc=%s, category=%s, qty=%s, unit=%s, exp_date=%s, price=%s
            WHERE id=%s AND user_id=%s RETURNING id
        """, (updates.item_name, updates.dsc, updates.category, updates.qty, updates.unit, updates.exp_date, updates.price, item_id, user_id))
        updated = cur.fetchone()
        if not updated:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Item not found or not owned by user")
        conn.commit()
        return {"message": "Item updated", "item_id": updated["id"]}
    except Exception as e:
        conn.rollback()
        logger.exception("Update item failed")
        raise HTTPException(status_code=500, detail="Update item failed")
    finally:
        cur.close()
        conn.close()

@app.delete("/delete_item/{user_id}/{item_id}")
def delete_item(user_id: int, item_id: int, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
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
    except Exception as e:
        conn.rollback()
        logger.exception("Delete item failed")
        raise HTTPException(status_code=500, detail="Delete item failed")
    finally:
        cur.close()
        conn.close()

# -----------------------
# Alerts
# -----------------------
@app.post("/alerts/{user_id}/{inventory_id}")
def create_alert(user_id: int, inventory_id: int, body: ExpiryAlertIn, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM inventory WHERE id=%s AND user_id=%s", (inventory_id, user_id))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Inventory item not found for this user")
        cur.execute("INSERT INTO expiry_alerts (user_id, inventory_id, alert_date, msg) VALUES (%s,%s,%s,%s) RETURNING id",
                    (user_id, inventory_id, datetime.utcnow().date(), body.msg))
        new = cur.fetchone()
        conn.commit()
        return {"message": "Alert created", "alert_id": new["id"] if new else None}
    except Exception as e:
        conn.rollback()
        logger.exception("Create alert failed")
        raise HTTPException(status_code=500, detail="Create alert failed")
    finally:
        cur.close()
        conn.close()

@app.get("/alerts/{user_id}")
def list_alerts(user_id: int, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT ea.id, ea.inventory_id, ea.alert_date, ea.msg, i.item_name
            FROM expiry_alerts ea
            LEFT JOIN inventory i ON i.id = ea.inventory_id
            WHERE ea.user_id = %s
            ORDER BY ea.alert_date DESC
        """, (user_id,))
        rows = cur.fetchall()
        return {"alerts": rows}
    except Exception as e:
        logger.exception("List alerts failed")
        raise HTTPException(status_code=500, detail="List alerts failed")
    finally:
        cur.close()
        conn.close()

# -----------------------
# Token verify helper (for debugging / quick checks)
# -----------------------
@app.get("/verify")
def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    # Quick verification endpoint. Returns token payload if valid.
    payload = decode_token(creds.credentials)
    return {"ok": True, "payload": payload}

# -----------------------
# Health
# -----------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -----------------------
# Deterministic requirements (written at runtime if run directly)
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

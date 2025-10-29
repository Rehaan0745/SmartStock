# main.py
# SmartStock — backward-compatible FastAPI backend (psycopg2 + pool)
# - Keeps original endpoints and JSON shape expected by your frontend
# - Adds connection pooling, RealDictCursor usage, date serialization, and safer error handling

import os
import logging
from datetime import datetime, timedelta, date
from typing import Dict, Optional, Any
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from argon2 import PasswordHasher
import psycopg2
from psycopg2.extras import RealDictCursor, register_adapter, Json
from psycopg2 import pool, errors
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
    if not value:
        return ["*"]
    value = value.strip()
    if value == "*":
        return ["*"]
    # Accept comma-separated list
    return [o.strip() for o in value.split(",") if o.strip()]

# register adapter so psycopg2 can return json seamlessly if needed
register_adapter(dict, Json)

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
# FastAPI + CORS
# -----------------------
app = FastAPI(title="SmartStock API (compat)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# Connection Pool (psycopg2)
# -----------------------
MIN_CONNS = 1
MAX_CONNS = int(os.getenv("DB_POOL_MAX", "10"))

_dsn = {
    "host": DB_HOST,
    "database": DB_NAME,
    "user": DB_USER,
    "password": DB_PASS,
}
if DB_PORT:
    _dsn["port"] = DB_PORT
if DB_SSLMODE:
    _dsn["sslmode"] = DB_SSLMODE

try:
    pg_pool = pool.SimpleConnectionPool(MIN_CONNS, MAX_CONNS, **_dsn)
    logger.info("Postgres connection pool created (min=%d max=%d)", MIN_CONNS, MAX_CONNS)
except Exception:
    logger.exception("Failed creating Postgres connection pool")
    pg_pool = None  # we'll raise later when used

@contextmanager
def get_db_conn():
    if not pg_pool:
        raise HTTPException(status_code=500, detail="Database pool not available")
    conn = None
    try:
        conn = pg_pool.getconn()
        yield conn
    finally:
        if conn:
            pg_pool.putconn(conn)

# -----------------------
# Auth / JWT helpers
# -----------------------
security = HTTPBearer()
ph = PasswordHasher()

def create_token(payload: Dict[str, Any], expires_delta: timedelta, token_type: str) -> str:
    to_encode = payload.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta, "type": token_type})
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT returns str in v2.x
    return token

def decode_token(token: str) -> Dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_access_token(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication scheme")
    payload = decode_token(creds.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload

# -----------------------
# Pydantic models (inputs)
# -----------------------
class RegisterIn(BaseModel):
    username: str
    email: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str

class InventoryItemIn(BaseModel):
    # Accept canonical names; later normalize in endpoint to accept frontend shapes too
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
# Helpers: serialize rows (RealDict) -> JSON-friendly dicts
# -----------------------
def serialize_row(row: Dict) -> Dict:
    """
    Convert date objects to isoformat strings so JSON is safe for frontend.
    """
    out = {}
    for k, v in row.items():
        if isinstance(v, (datetime, date)):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out

# -----------------------
# Auth endpoints (register/login/refresh)
# -----------------------
@app.post("/register")
def register(user: RegisterIn):
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (user.username, user.email))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Username or Email already exists")
            hashed = ph.hash(user.password)
            try:
                cur.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (%s,%s,%s,%s) RETURNING id",
                    (user.username, user.email, hashed, datetime.utcnow())
                )
            except errors.UniqueViolation:
                conn.rollback()
                raise HTTPException(status_code=400, detail="Username or Email already exists")
            new = cur.fetchone()
            conn.commit()
            return {"message": "Registration successful", "user_id": new["id"] if new else None}
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            logger.exception("Registration failed")
            raise HTTPException(status_code=500, detail="Registration failed")
        finally:
            cur.close()

@app.post("/login")
def login(credentials: LoginIn):
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
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
            # Return same shape as original frontend expected
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

@app.post("/refresh")
def refresh(req: RefreshIn):
    # Validate refresh token and issue new access token
    try:
        payload = jwt.decode(req.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    # Optional: verify user still exists
    user_sub = payload.get("sub")
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid refresh token payload")
    # issue new access
    new_access = create_token({"sub": payload.get("sub"), "username": payload.get("username")}, timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES), "access")
    return {"access_token": new_access, "token_type": "bearer", "expires_in_minutes": ACCESS_TOKEN_EXPIRES_MINUTES}

# -----------------------
# Inventory endpoints
# -----------------------
@app.get("/inventory")
def get_inventory(token_payload: Dict = Depends(require_access_token)):
    user_id = token_payload.get("sub")
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("""
                SELECT id, user_id, item_name, dsc, category, qty, unit, date_added, exp_date, price
                FROM inventory WHERE user_id = %s ORDER BY date_added DESC
            """, (user_id,))
            items = cur.fetchall()
            # normalize rows (iso dates)
            payload = [serialize_row(r) for r in items]
            return {"items": payload, "inventory": payload}
        except Exception:
            logger.exception("Fetch inventory failed")
            raise HTTPException(status_code=500, detail="Fetch inventory failed")
        finally:
            cur.close()

@app.get("/inventory/{user_id}")
def get_inventory_by_user(user_id: int, token_payload: Dict = Depends(require_access_token)):
    # ensure token belongs to the requesting user
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to requested user")
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("""
                SELECT id, user_id, item_name, dsc, category, qty, unit, date_added, exp_date, price
                FROM inventory WHERE user_id = %s ORDER BY date_added DESC
            """, (user_id,))
            items = cur.fetchall()
            payload = [serialize_row(r) for r in items]
            return {"items": payload, "inventory": payload}
        except Exception:
            logger.exception("Fetch inventory by user failed")
            raise HTTPException(status_code=500, detail="Fetch inventory failed")
        finally:
            cur.close()

# Accept both InventoryItemIn and frontend-friendly shapes (name/quantity/expiry)
def normalize_item_payload(body: Dict) -> Dict:
    """
    Accepts either:
      - item_name, qty, price, exp_date, category, dsc, unit
    or - name, quantity, price, expiry, category
    Returns normalized dict matching DB columns: item_name, dsc, category, qty, unit, exp_date, price
    """
    # if body is a Pydantic model object it may be .dict(); caller should pass dict
    b = dict(body)
    normalized = {}
    # name
    normalized['item_name'] = b.get('item_name') or b.get('name') or b.get('item') or ''
    normalized['dsc'] = b.get('dsc') or b.get('description') or ''
    normalized['category'] = b.get('category') or b.get('cat') or None
    # qty / quantity
    q = b.get('qty')
    if q is None:
        q = b.get('quantity')
    try:
        normalized['qty'] = int(q) if q is not None else 0
    except Exception:
        normalized['qty'] = 0
    normalized['unit'] = b.get('unit') or None
    # exp date mapping: exp_date or expiry
    exp = b.get('exp_date') or b.get('expiry') or b.get('exp')
    # Normalize empty strings -> None
    normalized['exp_date'] = exp or None
    # price
    p = b.get('price')
    try:
        normalized['price'] = float(p) if p is not None else 0.0
    except Exception:
        normalized['price'] = 0.0
    return normalized

@app.post("/add_item/{user_id}")
def add_item(user_id: int, item: dict, token_payload: Dict = Depends(require_access_token)):
    """
    Accepts flexible JSON payload from frontend. Normalizes keys before insert.
    """
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to target user")
    data = normalize_item_payload(item)
    # validate minimal
    if not data['item_name'] or data['qty'] is None:
        raise HTTPException(status_code=400, detail="Invalid item payload")
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("""
                INSERT INTO inventory (user_id, item_name, dsc, category, qty, unit, exp_date, price)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
            """, (user_id, data['item_name'], data['dsc'], data['category'], data['qty'], data['unit'], data['exp_date'], data['price']))
            new = cur.fetchone()
            conn.commit()
            return {"message": "Item added", "item_id": new["id"] if new else None}
        except Exception:
            conn.rollback()
            logger.exception("Add item failed")
            raise HTTPException(status_code=500, detail="Add item failed")
        finally:
            cur.close()

@app.put("/update_item/{user_id}/{item_id}")
def update_item(user_id: int, item_id: int, updates: dict, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
    data = normalize_item_payload(updates)
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("""
                UPDATE inventory SET item_name=%s, dsc=%s, category=%s, qty=%s, unit=%s, exp_date=%s, price=%s
                WHERE id=%s AND user_id=%s RETURNING id
            """, (data['item_name'], data['dsc'], data['category'], data['qty'], data['unit'], data['exp_date'], data['price'], item_id, user_id))
            updated = cur.fetchone()
            if not updated:
                conn.rollback()
                raise HTTPException(status_code=404, detail="Item not found or not owned by user")
            conn.commit()
            return {"message": "Item updated", "item_id": updated["id"]}
        except HTTPException:
            raise
        except Exception:
            conn.rollback()
            logger.exception("Update item failed")
            raise HTTPException(status_code=500, detail="Update item failed")
        finally:
            cur.close()

@app.delete("/delete_item/{user_id}/{item_id}")
def delete_item(user_id: int, item_id: int, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("DELETE FROM inventory WHERE id=%s AND user_id=%s RETURNING id", (item_id, user_id))
            deleted = cur.fetchone()
            if not deleted:
                conn.rollback()
                raise HTTPException(status_code=404, detail="Item not found or not owned by user")
            conn.commit()
            return {"message": "Item deleted"}
        except Exception:
            conn.rollback()
            logger.exception("Delete item failed")
            raise HTTPException(status_code=500, detail="Delete item failed")
        finally:
            cur.close()

# -----------------------
# Alerts
# -----------------------
@app.post("/alerts/{user_id}/{inventory_id}")
def create_alert(user_id: int, inventory_id: int, body: ExpiryAlertIn, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("SELECT id FROM inventory WHERE id=%s AND user_id=%s", (inventory_id, user_id))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Inventory item not found for this user")
            cur.execute("INSERT INTO expiry_alerts (user_id, inventory_id, alert_date, msg) VALUES (%s,%s,%s,%s) RETURNING id",
                        (user_id, inventory_id, datetime.utcnow().date(), body.msg))
            new = cur.fetchone()
            conn.commit()
            return {"message": "Alert created", "alert_id": new["id"] if new else None}
        except Exception:
            conn.rollback()
            logger.exception("Create alert failed")
            raise HTTPException(status_code=500, detail="Create alert failed")
        finally:
            cur.close()

@app.get("/alerts/{user_id}")
def list_alerts(user_id: int, token_payload: Dict = Depends(require_access_token)):
    if str(token_payload.get("sub")) != str(user_id):
        raise HTTPException(status_code=403, detail="Token does not belong to user")
    with get_db_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("""
                SELECT ea.id, ea.inventory_id, ea.alert_date, ea.msg, i.item_name
                FROM expiry_alerts ea
                LEFT JOIN inventory i ON i.id = ea.inventory_id
                WHERE ea.user_id = %s
                ORDER BY ea.alert_date DESC
            """, (user_id,))
            rows = cur.fetchall()
            payload = [serialize_row(r) for r in rows]
            return {"alerts": payload}
        except Exception:
            logger.exception("List alerts failed")
            raise HTTPException(status_code=500, detail="List alerts failed")
        finally:
            cur.close()

# -----------------------
# Token verify helper
# -----------------------
@app.get("/verify")
def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(creds.credentials)
    return {"ok": True, "payload": payload}

# -----------------------
# Health
# -----------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -----------------------
# Clean shutdown helper (optional)
# -----------------------
import atexit
def _close_pool():
    global pg_pool
    try:
        if pg_pool:
            pg_pool.closeall()
            logger.info("Postgres pool closed")
    except Exception:
        logger.exception("Closing pool failed")
atexit.register(_close_pool)

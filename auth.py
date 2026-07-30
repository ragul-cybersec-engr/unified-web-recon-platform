from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import bcrypt
from datetime import datetime, timedelta
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

SECRET = "Team123!@#Secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()

# Simple user store - in production replace with proper user DB
_USERS_FILE = "data/users.json"
_USERS_LOCK = threading.Lock()

# OTP in-memory store
_OTP_STORE = {}
_OTP_LOCK = threading.Lock()
OTP_EXPIRY_SECONDS = 300
OTP_MAX_ATTEMPTS = 5


def _normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def _ensure_users_file():
    p = Path(_USERS_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("{}", encoding="utf-8")


def _load_users():
    _ensure_users_file()
    p = Path(_USERS_FILE)
    with _USERS_LOCK:
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}


def _save_users(users: dict):
    _ensure_users_file()
    p = Path(_USERS_FILE)
    with _USERS_LOCK:
        p.write_text(json.dumps(users, indent=2), encoding="utf-8")


def user_exists(email: str) -> bool:
    users = _load_users()
    return _normalize_email(email) in users


def register_user(email: str, password: str, name: str, role: str = "user") -> dict:
    email_key = _normalize_email(email)
    _ensure_users_file()
    p = Path(_USERS_FILE)
    with _USERS_LOCK:
        try:
            users = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            users = {}
        if email_key in users:
            raise ValueError("User already exists")
        user = {
            "email": email_key,
            "password": hash_password(password),
            "name": name,
            "role": role,
        }
        users[email_key] = user
        p.write_text(json.dumps(users, indent=2), encoding="utf-8")
        return user


def create_login_otp(email: str) -> str:
    email_key = _normalize_email(email)
    now = time.time()
    code = f"{secrets.randbelow(1000000):06d}"
    with _OTP_LOCK:
        rec = _OTP_STORE.get(email_key)
        if rec and now <= rec["expires_at"]:
            rec["attempts"] = 0
            return rec["code"]
        _OTP_STORE[email_key] = {
            "code": code,
            "expires_at": now + OTP_EXPIRY_SECONDS,
            "attempts": 0,
        }
    return code


def verify_login_otp(email: str, otp: str) -> bool:
    email_key = _normalize_email(email)
    cleaned_otp = "".join(ch for ch in str(otp) if ch.isdigit())
    with _OTP_LOCK:
        rec = _OTP_STORE.get(email_key)
        if not rec:
            return False
        if time.time() > rec["expires_at"]:
            _OTP_STORE.pop(email_key, None)
            return False
        if not secrets.compare_digest(str(rec["code"]), cleaned_otp):
            rec["attempts"] += 1
            if rec["attempts"] >= OTP_MAX_ATTEMPTS:
                _OTP_STORE.pop(email_key, None)
            return False
        _OTP_STORE.pop(email_key, None)
        return True


def has_active_login_otp(email: str) -> bool:
    email_key = _normalize_email(email)
    with _OTP_LOCK:
        rec = _OTP_STORE.get(email_key)
        if not rec:
            return False
        if time.time() > rec["expires_at"]:
            _OTP_STORE.pop(email_key, None)
            return False
        return True


def authenticate_user(email: str, password: str) -> Optional[dict]:
    users = _load_users()
    u = users.get(_normalize_email(email))
    if not u:
        return None
    if not verify_password(password, u["password"]):
        return None
    return u


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        raw_email = payload.get("sub")
        email = _normalize_email(raw_email)
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    users = _load_users()
    u = users.get(email)
    if not u:
        raise HTTPException(status_code=401, detail="User not found")
    return u


# Simple in-memory rate limiter
_RATE = {}
RATE_LIMIT_PER_MIN = 10


def rate_limit(email: str):
    import time
    now = int(time.time())
    window = now // 60
    key = f"{email}:{window}"
    _RATE.setdefault(key, 0)
    _RATE[key] += 1
    if _RATE[key] > RATE_LIMIT_PER_MIN:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

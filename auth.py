import os
import hmac
import time
import hashlib
import secrets
import smtplib
import sqlite3
from email.mime.text import MIMEText
from typing import Callable
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash

from database import get_db_connection

# Environment configuration
APP_ENV = os.getenv("APP_ENV", "production").strip().lower()
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing. Set it before starting the app.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OTP_TTL_SECONDS = 300
MAX_OTP_ATTEMPTS = 3

# Password hash utility using pwdlib (Argon2 / recommended)
password_hash = PasswordHash.recommended()

# In-memory OTP store: {email: {"otp_hash": str, "expires_at": float, "attempts": int, "used": bool}}
_otp_store: dict[str, dict] = {}

router = APIRouter(prefix="/auth", tags=["Authentication & Authorization"])
bearer_scheme = HTTPBearer(auto_error=False)


# ==========================================
# PYDANTIC SCHEMAS
# ==========================================
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class OTPRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def _hash_otp(email: str, otp: str) -> str:
    return hmac.new(
        SECRET_KEY.encode("utf-8"),
        f"{email.lower()}:{otp}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _send_otp_email(recipient: str, otp: str) -> None:
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    if not smtp_user or not smtp_pass:
        if APP_ENV == "production":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OTP delivery service is not configured.",
            )
        return

    msg = MIMEText(f"Your security verification code is: {otp}\nIt expires in 5 minutes.")
    msg["Subject"] = "Security Verification Code"
    msg["From"] = smtp_user
    msg["To"] = recipient

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


def create_access_token(user_id: int, role: str):
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expires,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    """Validates the JWT signature, expiry, and required claims on every protected request."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "role", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
        )

    return {"sub": payload["sub"], "role": payload["role"]}


def require_role(*allowed_roles: str) -> Callable:
    """Dependency factory enforcing server-side RBAC for sensitive endpoints."""
    def _role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Required role: {', '.join(allowed_roles)}.",
            )
        return current_user

    return _role_checker


# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================
@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    username = data.username.strip()
    email = data.email.strip().lower()

    if not username or not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and email are required."
        )

    hashed_password = password_hash.hash(data.password)
    conn = get_db_connection()

    try:
        conn.execute(
            """
            INSERT INTO users (username, email, password)
            VALUES (?, ?, ?)
            """,
            (username, email, hashed_password),
        )
        conn.commit()

        return {
            "message": "Registration successful. You can now log in."
        }

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered."
        )
    finally:
        conn.close()


@router.post("/login")
def login(data: LoginRequest):
    identifier = data.username.strip()

    conn = get_db_connection()
    try:
        user = conn.execute(
            """
            SELECT id, username, email, password, role
            FROM users
            WHERE username = ? COLLATE NOCASE
               OR email = ? COLLATE NOCASE
            """,
            (identifier, identifier),
        ).fetchone()
    finally:
        conn.close()

    if not user or not password_hash.verify(data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password."
        )

    token = create_access_token(user["id"], user["role"])

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        },
    }


@router.post("/otp/request")
def request_otp(body: OTPRequest):
    """Generates a 6-digit OTP, stores only its HMAC-SHA256 digest, and never returns the OTP in production."""
    email = body.email.lower()
    otp_code = f"{secrets.randbelow(1_000_000):06d}"

    _otp_store[email] = {
        "otp_hash": _hash_otp(email, otp_code),
        "expires_at": time.time() + OTP_TTL_SECONDS,
        "attempts": 0,
        "used": False,
    }

    _send_otp_email(email, otp_code)

    response = {
        "status": "sent",
        "message": "If the account exists, a verification code has been sent to the registered email.",
    }

    if APP_ENV == "development":
        response["dev_debug_otp"] = otp_code

    return response


@router.post("/otp/verify")
def verify_otp(body: OTPVerifyRequest):
    """Enforces single-use, constant-time comparison, expiry, and brute-force lockout."""
    email = body.email.lower()
    record = _otp_store.get(email)

    if not record or record["used"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or already consumed verification code.",
        )

    if time.time() > record["expires_at"]:
        _otp_store.pop(email, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Verification code has expired.",
        )

    if record["attempts"] >= MAX_OTP_ATTEMPTS:
        _otp_store.pop(email, None)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum OTP verification attempts exceeded. Request a new code.",
        )

    expected_hash = record["otp_hash"]
    submitted_hash = _hash_otp(email, body.otp.strip())

    if not hmac.compare_digest(expected_hash, submitted_hash):
        record["attempts"] += 1
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code.",
        )

    record["used"] = True
    token = create_access_token(user_id=1, role="analyst") # Adjust user lookup/id as needed based on email if linking to db user
    return {"access_token": token, "token_type": "bearer"}
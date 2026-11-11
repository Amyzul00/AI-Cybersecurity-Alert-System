
import os
import jwt
import sqlite3

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from pwdlib import PasswordHash

from database import get_db_connection

router = APIRouter(prefix="/auth", tags=["Authentication"])

password_hash = PasswordHash.recommended()

# Set JWT_SECRET_KEY as an environment variable before deployment.
SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is missing. Set it before starting the app."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Request formats
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def create_access_token(user_id: int, role: str):
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expires,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/register", status_code=201)
def register(data: RegisterRequest):
    username = data.username.strip()
    email = data.email.strip().lower()

    if not username or not email:
        raise HTTPException(
            status_code=400,
            detail="Username and email are required."
        )

    hashed_password = password_hash.hash(data.password)
    conn = get_db_connection()

    try:
        conn.execute(
            """
            INSERT INTO users (username, email, hashed_password)
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
            status_code=409,
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
            SELECT id, username, email, hashed_password, role
            FROM users
            WHERE username = ? COLLATE NOCASE
               OR email = ? COLLATE NOCASE
            """,
            (identifier, identifier),
        ).fetchone()
    finally:
        conn.close()

    if not user or not password_hash.verify(
        data.password, user["hashed_password"]
    ):
        raise HTTPException(
            status_code=401,
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

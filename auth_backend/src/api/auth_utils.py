"""
Authentication utility logic for FastAPI 'auth_backend' – user password hasher, JWT encoder/decoder, and user DB access.

Uses environment variables for config:
    - JWT_SECRET_KEY
    - JWT_ALGORITHM
    - JWT_ACCESS_TOKEN_EXPIRE_MINUTES

Assumes an 'auth_database' dependency for user lookup and creation.
"""

import os
import datetime
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()  # Load .env configuration variables

# Read environment variables for JWT settings
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "CHANGEME_SECRET_KEY")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# PUBLIC_INTERFACE
def get_password_hash(password: str) -> str:
    """Hashes the password using bcrypt."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies that a plain password matches the hashed one."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    """Creates a JWT access token with expiration."""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# PUBLIC_INTERFACE
def decode_access_token(token: str) -> Optional[dict]:
    """Decodes and validates a JWT access token. Returns the payload, or None if invalid."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None

# --- Placeholder user database logic for now ---
# Replace with real database logic.
class FakeUserDB:
    """In-memory user mock DB. Replace with real DB calls (auth_database dependency)."""
    _users = {}  # username: hashed_password

    @classmethod
    def get_user(cls, username):
        return cls._users.get(username)

    @classmethod
    def create_user(cls, username, password_hash):
        cls._users[username] = password_hash

    @classmethod
    def user_exists(cls, username):
        return username in cls._users

# PUBLIC_INTERFACE
def get_user_by_username(username: str):
    """Fetch user data from the database by username."""
    # Implement with real DB call (auth_database)
    password_hash = FakeUserDB.get_user(username)
    if not password_hash:
        return None
    return {"username": username, "hashed_password": password_hash}

# PUBLIC_INTERFACE
def create_user(username: str, password: str):
    """Store a new user in database (replace with real DB logic)."""
    if FakeUserDB.user_exists(username):
        raise ValueError("User already exists.")
    password_hash = get_password_hash(password)
    FakeUserDB.create_user(username, password_hash)
    return {"username": username}


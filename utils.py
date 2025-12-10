# utils.py

import json
from flask_login import current_user
from passlib.context import CryptContext
from cryptography.fernet import Fernet

from config import USER_FILE
from keys import SECRET_KEY, ENCRYPTION_KEY, fernet

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def load_users():
    """Load users from the JSON file."""
    try:
        with open(USER_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_users(users: dict):
    """Save users to the JSON file."""
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)


def verify_password(plain: str, hashed: str) -> bool:
    """Check a plaintext password against a hash."""
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def encrypt_message(text: str, fernet_obj: Fernet = fernet) -> bytes:
    """Encrypt a string using Fernet."""
    return fernet_obj.encrypt(text.encode())


def decrypt_message(blob: bytes, fernet_obj: Fernet = fernet) -> str:
    
    """Decrypt a Fernet-encrypted message."""
    return fernet_obj.decrypt(blob).decode()



def is_admin() -> bool:
    """Check if the current user has admin role."""
    if not current_user.is_authenticated:
        return False

    users = load_users()
    user_data = users.get(current_user.username, {})
    return user_data.get("role") == "admin"

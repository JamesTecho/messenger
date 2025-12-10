# hash_password.py
from passlib.context import CryptContext
import sys


pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hash_password.py <password_to_hash>")
        sys.exit(1)
        
    password = sys.argv[1]
    hashed_password = pwd_context.hash(password)
    print(f"Hashed Password for '{password}':")
    print(hashed_password)
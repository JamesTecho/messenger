# keys.py

import os
import uuid
from cryptography.fernet import Fernet

# Flask secret key
if os.environ.get("FLASK_SECRET"):
    SECRET_KEY = os.environ["FLASK_SECRET"].encode()
elif os.path.exists("flask_secret.key"):
    SECRET_KEY = open("flask_secret.key", "rb").read()
else:
    SECRET_KEY = uuid.uuid4().bytes
    open("flask_secret.key", "wb").write(SECRET_KEY)

# Fernet encryption key
if os.environ.get("FERNET_KEY"):
    ENCRYPTION_KEY = os.environ["FERNET_KEY"].encode()
elif os.path.exists("fernet.key"):
    ENCRYPTION_KEY = open("fernet.key", "rb").read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    open("fernet.key", "wb").write(ENCRYPTION_KEY)

fernet = Fernet(ENCRYPTION_KEY)

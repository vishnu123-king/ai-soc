import hashlib
import secrets
import bcrypt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False
    try:
        password_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    password_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")

def generate_agent_token() -> str:
    """Generates a secure random 32-byte hex token for agent authorization"""
    return secrets.token_hex(32)

def hash_agent_token(token: str) -> str:
    """Hashes the agent token with SHA-256 for secure storage"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


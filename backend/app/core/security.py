import os
import hmac
import hashlib
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from app.core.config import settings

# Attempt to import bcrypt; fall back to standard library PBKDF2 if bcrypt is not yet installed
try:
    import bcrypt

    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def verify_password(plain_password: str, hashed_password: str) -> bool:
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception:
            return False

except ImportError:
    # Standard library NIST-compliant PBKDF2 fallback
    def hash_password(password: str) -> str:
        salt = os.urandom(16).hex()
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return f"pbkdf2:sha256:{salt}:{dk.hex()}"

    def verify_password(plain_password: str, hashed_password: str) -> bool:
        try:
            parts = hashed_password.split(":")
            if len(parts) != 4 or parts[0] != "pbkdf2":
                return False
            _, algo, salt, expected_hash = parts
            dk = hashlib.pbkdf2_hmac(algo, plain_password.encode("utf-8"), salt.encode("utf-8"), 100000)
            return hmac.compare_digest(dk.hex(), expected_hash)
        except Exception:
            return False


# Attempt to import PyJWT; fall back to signed HMAC-SHA256 JWT representation if not yet installed
try:
    import jwt

    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return payload
        except jwt.PyJWTError:
            return None

except ImportError:
    # Lightweight standard library signed JWT fallback
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    def _b64url_decode(s: str) -> bytes:
        padding = 4 - (len(s) % 4)
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s.encode("utf-8"))

    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = (datetime.utcnow() + expires_delta).timestamp()
        else:
            expire = (datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()
        to_encode.update({"exp": expire})
        
        header = json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")
        payload = json.dumps(to_encode).encode("utf-8")
        header_b64 = _b64url_encode(header)
        payload_b64 = _b64url_encode(payload)
        
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = hmac.new(settings.SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
        signature_b64 = _b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header_b64, payload_b64, signature_b64 = parts
            signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
            expected_sig = hmac.new(settings.SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(_b64url_encode(expected_sig), signature_b64):
                return None
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
            if "exp" in payload and datetime.utcnow().timestamp() > payload["exp"]:
                return None  # Token expired
            return payload
        except Exception:
            return None

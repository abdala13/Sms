from datetime import datetime, timedelta, timezone
from itsdangerous import BadSignature, URLSafeSerializer
from passlib.context import CryptContext
from app.core.config import get_settings

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
serializer = URLSafeSerializer(get_settings().secret_key, salt='curlflow-session')


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_session_token(user_id: int) -> str:
    payload = {'sub': user_id, 'exp': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()}
    return serializer.dumps(payload)


def decode_session_token(token: str) -> int | None:
    try:
        payload = serializer.loads(token)
    except BadSignature:
        return None
    try:
        exp = datetime.fromisoformat(payload['exp'])
        if exp < datetime.now(timezone.utc):
            return None
        return int(payload['sub'])
    except Exception:
        return None

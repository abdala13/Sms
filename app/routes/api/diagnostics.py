from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix='/api/diagnostics', tags=['diagnostics'])


@router.get('/health')
def health(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    ok = True
    try:
        db.execute(text('SELECT 1'))
    except Exception:
        ok = False
    return {
        'status': 'ok' if ok else 'degraded',
        'database': ok,
        'redis_url': get_settings().redis_url,
        'app_env': get_settings().app_env,
    }

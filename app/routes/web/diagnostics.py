from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix='/diagnostics')


@router.get('', response_class=HTMLResponse)
def diagnostics_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_ok = True
    try:
        db.execute(text('SELECT 1'))
    except Exception:
        db_ok = False
    data = {
        'now': datetime.utcnow(),
        'db_ok': db_ok,
        'redis_url': get_settings().redis_url,
        'database_url': get_settings().database_url,
        'app_env': get_settings().app_env,
        'max_workers_per_run': get_settings().max_workers_per_run,
    }
    return request.app.state.templates.TemplateResponse('diagnostics/index.html', {'request': request, 'user': current_user, 'diag': data})

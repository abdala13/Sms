from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.settings import ApprovedPackage
from app.models.user import User
from app.services.settings_resolver import resolve_shared_settings

router = APIRouter(prefix='/settings')


@router.get('', response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    settings = resolve_shared_settings(db, current_user.id)
    packages = db.query(ApprovedPackage).filter_by(is_active=True).all()
    return request.app.state.templates.TemplateResponse('settings/index.html', {'request': request, 'user': current_user, 'settings_obj': settings, 'packages': packages})


@router.post('')
def save_settings(shared_user_agents: str = Form(''), rate_limit_per_minute: int = Form(60), default_timeout_seconds: int = Form(20), retry_count: int = Form(2), repeated_failure_threshold: int = Form(5), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    settings = resolve_shared_settings(db, current_user.id)
    settings.shared_user_agents_json = [x.strip() for x in shared_user_agents.splitlines() if x.strip()]
    settings.rate_limit_per_minute = rate_limit_per_minute
    settings.default_timeout_seconds = default_timeout_seconds
    settings.retry_count = retry_count
    settings.repeated_failure_threshold = repeated_failure_threshold
    db.commit()
    return RedirectResponse('/settings', status_code=303)

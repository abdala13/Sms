from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.script import Script
from app.models.user import User
from app.services.report_service import ReportService

router = APIRouter()


@router.get('/', include_in_schema=False)
def root():
    return RedirectResponse('/dashboard')


@router.get('/dashboard', response_class=HTMLResponse)
def dashboard(
    request: Request,
    q: str | None = Query(default=None),
    favorites: int = Query(default=0),
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scripts_query = db.query(Script).filter_by(owner_id=current_user.id)
    if q:
        like = f'%{q}%'
        scripts_query = scripts_query.filter(or_(Script.name.ilike(like), Script.description.ilike(like), Script.target_url.ilike(like), Script.tags.cast(str).ilike(like)))
    if favorites:
        scripts_query = scripts_query.filter(Script.is_favorite.is_(True))
    scripts = scripts_query.order_by(Script.created_at.desc()).all()
    if status:
        scripts = [s for s in scripts if (s.runs[-1].status if s.runs else 'ready') == status]
    overview = ReportService.overview(db, current_user.id)
    return request.app.state.templates.TemplateResponse('dashboard/index.html', {
        'request': request,
        'user': current_user,
        'scripts': scripts,
        'overview': overview,
        'filters': {'q': q or '', 'favorites': favorites, 'status': status or ''},
    })

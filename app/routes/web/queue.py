from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.run import Run
from app.models.user import User

router = APIRouter(prefix='/queue')


@router.get('', response_class=HTMLResponse)
def queue_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    active = db.query(Run).filter(Run.owner_id == current_user.id, Run.status.in_(['queued', 'running', 'paused_verification'])).order_by(Run.id.desc()).all()
    recent = db.query(Run).filter(Run.owner_id == current_user.id).order_by(Run.id.desc()).limit(30).all()
    return request.app.state.templates.TemplateResponse('queue/index.html', {'request': request, 'user': current_user, 'active_runs': active, 'recent_runs': recent})

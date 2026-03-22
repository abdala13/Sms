from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.services.report_service import ReportService

router = APIRouter(prefix='/reports')


@router.get('', response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    overview = ReportService.overview(db, current_user.id)
    daily = ReportService.daily_runs(db, current_user.id)
    return request.app.state.templates.TemplateResponse('reports/index.html', {'request': request, 'user': current_user, 'overview': overview, 'daily': daily})

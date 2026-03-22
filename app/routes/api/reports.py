from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.services.report_service import ReportService

router = APIRouter(prefix='/api/reports', tags=['reports'])


@router.get('/overview')
def overview(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    data = ReportService.overview(db, current_user.id)
    return {
        'total_scripts': data['total_scripts'],
        'total_runs': data['total_runs'],
        'active_runs': data['active_runs'],
        'success_rate': data['success_rate'],
        'challenge_count': data['challenge_count'],
        'top_scripts': [{'name': name, 'runs_count': count} for name, count in data['top_scripts']],
        'top_errors': [{'error_type': err, 'count': count} for err, count in data['top_errors']],
    }

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.settings import ApprovedPackage
from app.models.user import User
from app.services.settings_resolver import resolve_shared_settings

router = APIRouter(prefix='/api/settings', tags=['settings'])


@router.get('/shared')
def get_shared(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    settings = resolve_shared_settings(db, current_user.id)
    return {'shared_user_agents_json': settings.shared_user_agents_json, 'network_policy_json': settings.network_policy_json, 'rate_limit_per_minute': settings.rate_limit_per_minute, 'default_timeout_seconds': settings.default_timeout_seconds, 'retry_count': settings.retry_count, 'repeated_failure_threshold': settings.repeated_failure_threshold}


@router.get('/approved-packages')
def approved_packages(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    packages = db.query(ApprovedPackage).filter_by(is_active=True).all()
    return [{'package_name': p.package_name, 'category': p.category} for p in packages]

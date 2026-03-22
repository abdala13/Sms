from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.script import Script
from app.models.user import User

router = APIRouter(prefix='/api/scripts', tags=['scripts'])


@router.get('')
def list_scripts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scripts = db.query(Script).filter_by(owner_id=current_user.id).all()
    return [{'id': s.id, 'name': s.name, 'method': s.method, 'target_url': s.target_url, 'created_at': s.created_at.isoformat(), 'is_favorite': s.is_favorite, 'last_run_at': s.last_run_at.isoformat() if s.last_run_at else None, 'tags': s.tags} for s in scripts]


@router.get('/{script_id}')
def get_script(script_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    return {'id': script.id, 'name': script.name, 'description': script.description, 'request_definition': script.request_definition, 'generated_code': script.generated_code, 'dependencies': [{'package_name': d.package_name, 'is_approved': d.is_approved} for d in script.dependencies], 'tags': script.tags, 'runtime_profile_id': script.runtime_profile_id}

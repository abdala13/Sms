from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.run import Run, RunEvent, RunItem
from app.models.user import User

router = APIRouter(prefix='/api/runs', tags=['runs'])


@router.get('/active')
def active_runs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    runs = db.query(Run).filter(Run.owner_id == current_user.id, Run.status.in_(['queued', 'running', 'paused_verification'])).all()
    return [{'id': r.id, 'script_id': r.script_id, 'status': r.status, 'progress_percent': r.progress_percent, 'retry_count': r.retry_count, 'stop_requested': bool(r.stop_requested)} for r in runs]


@router.get('/queue')
def queue_overview(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    runs = db.query(Run).filter(Run.owner_id == current_user.id).order_by(Run.id.desc()).limit(50).all()
    return [{'id': r.id, 'script_id': r.script_id, 'status': r.status, 'progress_percent': r.progress_percent, 'processed_items': r.processed_items, 'total_items': r.total_items} for r in runs]


@router.get('/{run_id}')
def get_run(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = db.query(Run).filter_by(id=run_id, owner_id=current_user.id).first()
    if not run:
        raise HTTPException(404)
    return {'id': run.id, 'status': run.status, 'progress_percent': run.progress_percent, 'processed_items': run.processed_items, 'success_count': run.success_count, 'failure_count': run.failure_count, 'retry_count': run.retry_count, 'stop_reason': run.stop_reason, 'summary_message': run.summary_message}


@router.get('/{run_id}/items')
def run_items(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = db.query(Run).filter_by(id=run_id, owner_id=current_user.id).first()
    if not run:
        raise HTTPException(404)
    items = db.query(RunItem).filter_by(run_id=run.id).order_by(RunItem.sequence_no.asc()).all()
    return [{'sequence_no': i.sequence_no, 'input_value': i.input_value, 'status': i.status, 'http_status_code': i.http_status_code, 'result_message': i.result_message, 'attempt_count': i.attempt_count, 'error_type': i.error_type} for i in items]


@router.get('/{run_id}/events')
def run_events(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = db.query(Run).filter_by(id=run_id, owner_id=current_user.id).first()
    if not run:
        raise HTTPException(404)
    events = db.query(RunEvent).filter_by(run_id=run.id).order_by(RunEvent.id.desc()).limit(100).all()
    return [{'id': e.id, 'event_type': e.event_type, 'message': e.message, 'created_at': e.created_at.isoformat(), 'details': e.details_json} for e in events]

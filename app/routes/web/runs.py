import json
import time
from datetime import datetime
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.run import Run, RunEvent, RunItem
from app.models.script import Script
from app.models.user import User
from app.services.settings_resolver import resolve_shared_settings
from app.tasks.run_tasks import execute_run_task

router = APIRouter(prefix='/runs')


@router.post('/start/{script_id}')
def start_run(
    script_id: int,
    workers: int = Form(1),
    delay_ms: int = Form(0),
    max_requests_per_minute: int = Form(60),
    repeated_failure_threshold: int = Form(5),
    max_failure_ratio: float = Form(1.0),
    processing_mode: str = Form('sequential'),
    continue_on_error: bool = Form(True),
    dry_run: bool = Form(False),
    use_shared_user_agents: bool = Form(True),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    shared = resolve_shared_settings(db, current_user.id)
    options = {
        'iterations': 1,
        'processing_mode': processing_mode,
        'workers': workers,
        'delay_ms': delay_ms,
        'max_requests_per_minute': max_requests_per_minute,
        'continue_on_error': continue_on_error,
        'stop_on_repeated_failures': True,
        'repeated_failure_threshold': repeated_failure_threshold,
        'max_failure_ratio': max_failure_ratio,
        'dry_run': dry_run,
        'use_shared_user_agents': use_shared_user_agents,
    }
    run = Run(
        script_id=script.id,
        owner_id=current_user.id,
        status='queued',
        total_items=len(script.inputs) or 1,
        resolved_settings_snapshot_json={
            'default_timeout_seconds': shared.default_timeout_seconds,
            'rate_limit_per_minute': shared.rate_limit_per_minute,
            'retry_count': shared.retry_count,
            'shared_user_agents_json': shared.shared_user_agents_json,
        },
        runtime_options_snapshot_json=options,
        last_activity_at=datetime.utcnow(),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    values = [i.normalized_value for i in script.inputs if i.is_active] or ['']
    for idx, value in enumerate(values, start=1):
        db.add(RunItem(run_id=run.id, input_value=value, sequence_no=idx))
    db.add(RunEvent(run_id=run.id, event_type='queued', message='Run queued', details_json={}))
    script.last_run_at = datetime.utcnow()
    db.commit()
    execute_run_task.delay(run.id)
    return RedirectResponse(f'/runs/{run.id}/monitor', status_code=303)


@router.get('/{run_id}/monitor', response_class=HTMLResponse)
def monitor(run_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = db.query(Run).filter_by(id=run_id, owner_id=current_user.id).first()
    if not run:
        raise HTTPException(404)
    return request.app.state.templates.TemplateResponse('runs/monitor.html', {'request': request, 'run': run, 'user': current_user})


@router.post('/{run_id}/stop')
def stop_run(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = db.query(Run).filter_by(id=run_id, owner_id=current_user.id).first()
    if not run:
        raise HTTPException(404)
    run.stop_requested = 1
    run.stop_reason = 'Stopped by user'
    db.add(RunEvent(run_id=run.id, event_type='stop_requested', message='Stop requested by user', details_json={}))
    db.commit()
    return RedirectResponse(f'/runs/{run.id}/monitor', status_code=303)


@router.get('/{run_id}/stream')
def run_stream(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    def event_gen():
        last_id = 0
        while True:
            db.expire_all()
            run = db.query(Run).filter_by(id=run_id, owner_id=current_user.id).first()
            if not run:
                break
            events = db.query(RunEvent).filter(RunEvent.run_id == run_id, RunEvent.id > last_id).order_by(RunEvent.id.asc()).all()
            for ev in events:
                last_id = ev.id
                payload = {
                    'id': ev.id,
                    'type': ev.event_type,
                    'message': ev.message,
                    'details': ev.details_json,
                    'created_at': ev.created_at.isoformat(),
                    'run': {
                        'status': run.status,
                        'processed_items': run.processed_items,
                        'success_count': run.success_count,
                        'failure_count': run.failure_count,
                        'retry_count': run.retry_count,
                        'progress_percent': run.progress_percent,
                    },
                }
                yield f"data: {json.dumps(payload)}\n\n"
            if run.status in {'completed', 'failed', 'stopped', 'paused_verification'} and not events:
                payload = {'type': 'terminal', 'run': {'status': run.status, 'processed_items': run.processed_items, 'success_count': run.success_count, 'failure_count': run.failure_count, 'retry_count': run.retry_count, 'progress_percent': run.progress_percent}}
                yield f"data: {json.dumps(payload)}\n\n"
                break
            time.sleep(1)
    return StreamingResponse(event_gen(), media_type='text/event-stream')

from datetime import datetime
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.run import Run, RunEvent, RunItem
from app.models.script import Script
from app.models.user import User

router = APIRouter(prefix='/logs')


@router.get('', response_class=HTMLResponse)
def logs_page(
    request: Request,
    script_id: int | None = Query(default=None),
    run_id: int | None = Query(default=None),
    level: str | None = Query(default=None),
    item_status: str | None = Query(default=None),
    error_type: str | None = Query(default=None),
    q: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scripts = db.query(Script).filter_by(owner_id=current_user.id).order_by(Script.name.asc()).all()
    runs_query = db.query(Run).filter_by(owner_id=current_user.id)
    if script_id:
        runs_query = runs_query.filter(Run.script_id == script_id)
    runs = runs_query.order_by(Run.id.desc()).limit(100).all()

    events_query = db.query(RunEvent).join(Run, Run.id == RunEvent.run_id).filter(Run.owner_id == current_user.id)
    items_query = db.query(RunItem).join(Run, Run.id == RunItem.run_id).filter(Run.owner_id == current_user.id)
    if script_id:
        events_query = events_query.filter(Run.script_id == script_id)
        items_query = items_query.filter(Run.script_id == script_id)
    if run_id:
        events_query = events_query.filter(RunEvent.run_id == run_id)
        items_query = items_query.filter(RunItem.run_id == run_id)
    if level:
        events_query = events_query.filter(RunEvent.level == level)
    if item_status:
        items_query = items_query.filter(RunItem.status == item_status)
    if error_type:
        items_query = items_query.filter(RunItem.error_type == error_type)
    if q:
        like = f'%{q}%'
        events_query = events_query.filter(RunEvent.message.ilike(like))
        items_query = items_query.filter((RunItem.result_message.ilike(like)) | (RunItem.input_value.ilike(like)))
    events = events_query.order_by(RunEvent.id.desc()).limit(150).all()
    items = items_query.order_by(RunItem.id.desc()).limit(150).all()
    return request.app.state.templates.TemplateResponse('logs/index.html', {
        'request': request,
        'user': current_user,
        'scripts': scripts,
        'runs': runs,
        'events': events,
        'items': items,
        'selected_script_id': script_id,
        'selected_run_id': run_id,
        'selected_level': level or '',
        'selected_item_status': item_status or '',
        'selected_error_type': error_type or '',
        'query_text': q or '',
        'generated_at': datetime.utcnow(),
    })

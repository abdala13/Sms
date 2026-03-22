import io
import json
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.script import Script, ScriptDependency, ScriptInput
from app.models.settings import RuntimeProfile
from app.models.user import User
from app.services.audit_service import record_audit
from app.services.code_generator import CodeGeneratorService
from app.services.curl_parser import CurlParseError, CurlParserService
from app.services.dependency_resolver import DependencyResolverService

router = APIRouter(prefix='/scripts')


def _parse_tags(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(',') if part.strip()]


@router.get('/new', response_class=HTMLResponse)
def new_script(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    profiles = db.query(RuntimeProfile).order_by(RuntimeProfile.is_default.desc(), RuntimeProfile.name.asc()).all()
    return request.app.state.templates.TemplateResponse('scripts/new.html', {'request': request, 'user': current_user, 'profiles': profiles})


@router.post('/analyze', response_class=HTMLResponse)
def analyze_script(request: Request, curl: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        definition = CurlParserService.parse(curl)
    except CurlParseError as exc:
        profiles = db.query(RuntimeProfile).order_by(RuntimeProfile.is_default.desc(), RuntimeProfile.name.asc()).all()
        return request.app.state.templates.TemplateResponse('scripts/new.html', {'request': request, 'user': current_user, 'error': str(exc), 'curl': curl, 'profiles': profiles}, status_code=400)
    code = CodeGeneratorService.generate(definition)
    deps = DependencyResolverService.detect_from_definition(definition)
    profiles = db.query(RuntimeProfile).order_by(RuntimeProfile.is_default.desc(), RuntimeProfile.name.asc()).all()
    return request.app.state.templates.TemplateResponse('scripts/new.html', {'request': request, 'user': current_user, 'curl': curl, 'definition': definition, 'code': code, 'deps': deps, 'profiles': profiles})


@router.post('/create')
def create_script(
    request: Request,
    name: str = Form(...),
    description: str = Form(''),
    tags: str = Form(''),
    runtime_profile_id: int | None = Form(default=None),
    original_curl: str = Form(...),
    request_definition: str = Form(...),
    generated_code: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    definition = json.loads(request_definition)
    script = Script(
        owner_id=current_user.id,
        name=name,
        description=description,
        original_curl=original_curl,
        method=definition['method'],
        target_url=definition['url'],
        request_definition=definition,
        generated_code=generated_code,
        tags=_parse_tags(tags),
        runtime_profile_id=runtime_profile_id,
    )
    db.add(script)
    db.commit()
    db.refresh(script)
    for dep in DependencyResolverService.detect_from_definition(definition):
        db.add(ScriptDependency(script_id=script.id, **dep))
    db.commit()
    record_audit(db, current_user.id, 'script_created', 'script', str(script.id), {'name': script.name}, request.client.host if request.client else None)
    return RedirectResponse(f'/scripts/{script.id}', status_code=303)


@router.post('/import')
def import_script(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    raw = file.file.read().decode('utf-8', errors='ignore')
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f'Invalid JSON import: {exc}') from exc
    required = {'name', 'original_curl', 'request_definition'}
    missing = sorted(required - set(payload.keys()))
    if missing:
        raise HTTPException(400, f'Missing import keys: {", ".join(missing)}')
    definition = payload['request_definition']
    code = payload.get('generated_code') or CodeGeneratorService.generate(definition)
    script = Script(
        owner_id=current_user.id,
        name=payload['name'],
        description=payload.get('description', ''),
        original_curl=payload['original_curl'],
        method=definition['method'],
        target_url=definition['url'],
        request_definition=definition,
        generated_code=code,
        tags=payload.get('tags', []),
    )
    db.add(script)
    db.commit()
    db.refresh(script)
    for value in payload.get('inputs', []):
        norm = str(value).strip()
        if norm:
            db.add(ScriptInput(script_id=script.id, raw_value=norm, normalized_value=norm))
    for dep in DependencyResolverService.detect_from_definition(definition):
        db.add(ScriptDependency(script_id=script.id, **dep))
    db.commit()
    record_audit(db, current_user.id, 'script_imported', 'script', str(script.id), {'name': script.name}, request.client.host if request.client else None)
    return RedirectResponse(f'/scripts/{script.id}', status_code=303)


@router.get('/{script_id}', response_class=HTMLResponse)
def script_detail(script_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    profiles = db.query(RuntimeProfile).order_by(RuntimeProfile.is_default.desc(), RuntimeProfile.name.asc()).all()
    return request.app.state.templates.TemplateResponse('scripts/detail.html', {'request': request, 'user': current_user, 'script': script, 'profiles': profiles})


@router.post('/{script_id}/update')
def update_script(
    script_id: int,
    name: str = Form(...),
    description: str = Form(''),
    tags: str = Form(''),
    runtime_profile_id: int | None = Form(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    script.name = name
    script.description = description
    script.tags = _parse_tags(tags)
    script.runtime_profile_id = runtime_profile_id
    db.commit()
    return RedirectResponse(f'/scripts/{script.id}', status_code=303)


@router.post('/{script_id}/inputs')
def add_inputs(script_id: int, request: Request, text: str = Form(''), file: UploadFile | None = File(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    content = text
    if file:
        content = file.file.read().decode('utf-8', errors='ignore')
    values = [line.strip() for line in content.splitlines() if line.strip()]
    seen = {item.normalized_value for item in script.inputs}
    for value in values:
        norm = value.strip()
        if norm not in seen:
            db.add(ScriptInput(script_id=script.id, raw_value=value, normalized_value=norm))
            seen.add(norm)
    db.commit()
    return RedirectResponse(f'/scripts/{script.id}', status_code=303)


@router.post('/{script_id}/favorite')
def toggle_favorite(script_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    script.is_favorite = not script.is_favorite
    db.commit()
    return RedirectResponse('/dashboard', status_code=303)


@router.post('/{script_id}/clone')
def clone_script(script_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    clone = Script(
        owner_id=current_user.id,
        name=f'{script.name} (Clone)',
        description=script.description,
        original_curl=script.original_curl,
        method=script.method,
        target_url=script.target_url,
        request_definition=script.request_definition,
        generated_code=script.generated_code,
        tags=script.tags,
        runtime_profile_id=script.runtime_profile_id,
        is_favorite=False,
    )
    db.add(clone)
    db.commit()
    db.refresh(clone)
    for item in script.inputs:
        db.add(ScriptInput(script_id=clone.id, raw_value=item.raw_value, normalized_value=item.normalized_value, input_type=item.input_type))
    for dep in script.dependencies:
        db.add(ScriptDependency(script_id=clone.id, package_name=dep.package_name, version_spec=dep.version_spec, is_direct=dep.is_direct, is_approved=dep.is_approved))
    db.commit()
    return RedirectResponse(f'/scripts/{clone.id}', status_code=303)


@router.post('/{script_id}/delete')
def delete_script(script_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    db.delete(script)
    db.commit()
    return RedirectResponse('/dashboard', status_code=303)


@router.get('/{script_id}/export')
def export_script(script_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    script = db.query(Script).filter_by(id=script_id, owner_id=current_user.id).first()
    if not script:
        raise HTTPException(404)
    payload = {
        'name': script.name,
        'description': script.description,
        'original_curl': script.original_curl,
        'request_definition': script.request_definition,
        'generated_code': script.generated_code,
        'tags': script.tags,
        'inputs': [i.normalized_value for i in script.inputs],
    }
    buf = io.BytesIO(json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8'))
    headers = {'Content-Disposition': f'attachment; filename=script_{script.id}.json'}
    return StreamingResponse(buf, media_type='application/json', headers=headers)

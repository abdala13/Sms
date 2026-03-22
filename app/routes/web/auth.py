from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import create_session_token, hash_password, verify_password
from app.models.user import User
from app.services.audit_service import record_audit

router = APIRouter()


@router.get('/login', response_class=HTMLResponse)
def login_page(request: Request):
    return request.app.state.templates.TemplateResponse('auth/login.html', {'request': request})


@router.post('/login')
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return request.app.state.templates.TemplateResponse('auth/login.html', {'request': request, 'error': 'Invalid credentials'}, status_code=400)
    token = create_session_token(user.id)
    response = RedirectResponse('/dashboard', status_code=303)
    response.set_cookie(get_settings().session_cookie_name, token, httponly=True, secure=get_settings().session_cookie_secure, samesite='lax')
    record_audit(db, user.id, 'login', 'user', str(user.id), {})
    return response


@router.get('/register', response_class=HTMLResponse)
def register_page(request: Request):
    return request.app.state.templates.TemplateResponse('auth/register.html', {'request': request})


@router.post('/register')
def register(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = User(username=username, email=email, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    return RedirectResponse('/login', status_code=303)


@router.post('/logout')
def logout():
    response = RedirectResponse('/login', status_code=303)
    response.delete_cookie(get_settings().session_cookie_name)
    return response

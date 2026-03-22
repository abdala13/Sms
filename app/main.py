from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.core.database import Base, SessionLocal, engine
from app.models import *  # noqa: F401,F403
from app.models.settings import ApprovedPackage, RuntimeProfile
from app.routes.api import diagnostics as api_diag, parser, reports as api_reports, runs as api_runs, scripts as api_scripts, settings as api_settings
from app.routes.web import auth, dashboard, diagnostics, logs, queue, reports, runs, scripts, settings

app = FastAPI(title='CurlFlow Manager')
app.mount('/static', StaticFiles(directory='app/static'), name='static')
app.state.templates = Jinja2Templates(directory='app/templates')


@app.on_event('startup')
def on_startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        defaults = ['httpx', 'requests', 'pydantic', 'tenacity', 'beautifulsoup4', 'lxml', 'jinja2', 'orjson']
        existing = {x.package_name for x in db.query(ApprovedPackage).all()}
        for name in defaults:
            if name not in existing:
                db.add(ApprovedPackage(package_name=name, category='core'))
        if not db.query(RuntimeProfile).filter_by(name='Default HTTP').first():
            db.add(RuntimeProfile(name='Default HTTP', python_version='3.11', base_packages_json=['httpx', 'pydantic'], extra_packages_json=['tenacity'], is_default=True))
        db.commit()
    finally:
        db.close()


app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(scripts.router)
app.include_router(runs.router)
app.include_router(settings.router)
app.include_router(reports.router)
app.include_router(logs.router)
app.include_router(diagnostics.router)
app.include_router(queue.router)
app.include_router(parser.router)
app.include_router(api_scripts.router)
app.include_router(api_runs.router)
app.include_router(api_settings.router)
app.include_router(api_reports.router)
app.include_router(api_diag.router)

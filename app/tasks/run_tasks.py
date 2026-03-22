import asyncio
from app.core.database import SessionLocal
from app.models.run import Run
from app.services.execution_engine import execute_run
from app.tasks.celery_app import celery_app


@celery_app.task(name='app.tasks.run_tasks.execute_run_task')
def execute_run_task(run_id: int):
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run:
            asyncio.run(execute_run(db, run))
    finally:
        db.close()

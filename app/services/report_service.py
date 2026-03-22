from __future__ import annotations

from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.run import Run, RunItem
from app.models.script import Script


class ReportService:
    @staticmethod
    def overview(db: Session, owner_id: int) -> dict:
        total_scripts = db.query(func.count(Script.id)).filter(Script.owner_id == owner_id).scalar() or 0
        total_runs = db.query(func.count(Run.id)).filter(Run.owner_id == owner_id).scalar() or 0
        active_runs = db.query(func.count(Run.id)).filter(Run.owner_id == owner_id, Run.status.in_(['queued', 'running', 'paused_verification'])).scalar() or 0
        totals = db.query(func.coalesce(func.sum(Run.success_count), 0), func.coalesce(func.sum(Run.failure_count), 0)).filter(Run.owner_id == owner_id).one()
        success_total, failure_total = totals
        attempts = success_total + failure_total
        success_rate = round((success_total / attempts) * 100, 2) if attempts else 0.0
        recent_runs = db.query(Run).filter(Run.owner_id == owner_id).order_by(Run.id.desc()).limit(20).all()
        top_scripts = (
            db.query(Script.name, func.count(Run.id).label('runs_count'))
            .join(Run, Run.script_id == Script.id)
            .filter(Script.owner_id == owner_id)
            .group_by(Script.id)
            .order_by(func.count(Run.id).desc())
            .limit(5)
            .all()
        )
        errors = (
            db.query(RunItem.error_type, func.count(RunItem.id).label('count'))
            .join(Run, Run.id == RunItem.run_id)
            .filter(Run.owner_id == owner_id, RunItem.error_type.isnot(None))
            .group_by(RunItem.error_type)
            .order_by(func.count(RunItem.id).desc())
            .limit(10)
            .all()
        )
        challenge_count = db.query(func.count(RunItem.id)).join(Run, Run.id == RunItem.run_id).filter(Run.owner_id == owner_id, RunItem.status == 'challenged').scalar() or 0
        avg_duration_ms = db.query(func.avg(RunItem.duration_ms)).join(Run, Run.id == RunItem.run_id).filter(Run.owner_id == owner_id, RunItem.duration_ms.isnot(None)).scalar() or 0
        return {
            'total_scripts': total_scripts,
            'total_runs': total_runs,
            'active_runs': active_runs,
            'success_rate': success_rate,
            'recent_runs': recent_runs,
            'top_scripts': top_scripts,
            'top_errors': errors,
            'challenge_count': challenge_count,
            'avg_duration_ms': round(float(avg_duration_ms), 2) if avg_duration_ms else 0,
        }

    @staticmethod
    def daily_runs(db: Session, owner_id: int, days: int = 7) -> list[dict]:
        today = datetime.utcnow().date()
        results = []
        for offset in range(days - 1, -1, -1):
            day = today - timedelta(days=offset)
            start = datetime.combine(day, datetime.min.time())
            end = start + timedelta(days=1)
            rows = db.query(func.count(Run.id), func.coalesce(func.sum(Run.success_count), 0), func.coalesce(func.sum(Run.failure_count), 0)).filter(Run.owner_id == owner_id, Run.started_at >= start, Run.started_at < end).one()
            results.append({'date': day.isoformat(), 'runs': int(rows[0] or 0), 'success': int(rows[1] or 0), 'failure': int(rows[2] or 0)})
        return results

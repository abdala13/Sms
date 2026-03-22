from sqlalchemy.orm import Session
from app.models.audit import AuditLog


def record_audit(db: Session, user_id: int | None, action: str, entity_type: str, entity_id: str, metadata: dict | None = None, ip: str | None = None):
    db.add(AuditLog(user_id=user_id, action=action, entity_type=entity_type, entity_id=entity_id, metadata_json=metadata or {}, ip_address=ip))
    db.commit()

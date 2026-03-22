from sqlalchemy.orm import Session
from app.models.settings import SharedSettings


def resolve_shared_settings(db: Session, owner_id: int) -> SharedSettings:
    settings = db.query(SharedSettings).filter_by(owner_id=owner_id).first()
    if not settings:
        settings = SharedSettings(owner_id=owner_id)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings

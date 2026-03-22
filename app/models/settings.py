from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class SharedSettings(Base):
    __tablename__ = 'shared_settings'
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'), unique=True, index=True)
    shared_user_agents_json: Mapped[list] = mapped_column(JSON, default=list)
    network_policy_json: Mapped[dict] = mapped_column(JSON, default=dict)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=60)
    default_timeout_seconds: Mapped[int] = mapped_column(Integer, default=20)
    retry_count: Mapped[int] = mapped_column(Integer, default=2)
    repeated_failure_threshold: Mapped[int] = mapped_column(Integer, default=5)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ApprovedPackage(Base):
    __tablename__ = 'approved_packages'
    id: Mapped[int] = mapped_column(primary_key=True)
    package_name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(80), default='general')
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class RuntimeProfile(Base):
    __tablename__ = 'runtime_profiles'
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    python_version: Mapped[str] = mapped_column(String(20), default='3.11')
    base_packages_json: Mapped[list] = mapped_column(JSON, default=list)
    extra_packages_json: Mapped[list] = mapped_column(JSON, default=list)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

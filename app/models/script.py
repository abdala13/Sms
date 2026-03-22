from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Folder(Base):
    __tablename__ = 'folders'
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    name: Mapped[str] = mapped_column(String(120))
    parent_id: Mapped[int | None] = mapped_column(ForeignKey('folders.id'), nullable=True)


class Script(Base):
    __tablename__ = 'scripts'
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(Text, default='')
    original_curl: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(20))
    target_url: Mapped[str] = mapped_column(String(2048))
    request_definition: Mapped[dict] = mapped_column(JSON)
    generated_code: Mapped[str] = mapped_column(Text)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    folder_id: Mapped[int | None] = mapped_column(ForeignKey('folders.id'), nullable=True)
    runtime_profile_id: Mapped[int | None] = mapped_column(ForeignKey('runtime_profiles.id'), nullable=True)
    is_favorite: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    owner = relationship('User', back_populates='scripts')
    inputs = relationship('ScriptInput', back_populates='script', cascade='all, delete-orphan')
    runs = relationship('Run', back_populates='script', cascade='all, delete-orphan')
    dependencies = relationship('ScriptDependency', back_populates='script', cascade='all, delete-orphan')


class ScriptInput(Base):
    __tablename__ = 'script_inputs'
    id: Mapped[int] = mapped_column(primary_key=True)
    script_id: Mapped[int] = mapped_column(ForeignKey('scripts.id'), index=True)
    raw_value: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[str] = mapped_column(Text, index=True)
    input_type: Mapped[str] = mapped_column(String(30), default='text')
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    script = relationship('Script', back_populates='inputs')


class ScriptDependency(Base):
    __tablename__ = 'script_dependencies'
    id: Mapped[int] = mapped_column(primary_key=True)
    script_id: Mapped[int] = mapped_column(ForeignKey('scripts.id'), index=True)
    package_name: Mapped[str] = mapped_column(String(120))
    version_spec: Mapped[str] = mapped_column(String(50), default='')
    is_direct: Mapped[bool] = mapped_column(Boolean, default=True)
    is_approved: Mapped[bool] = mapped_column(Boolean, default=True)

    script = relationship('Script', back_populates='dependencies')

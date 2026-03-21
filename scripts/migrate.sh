#!/usr/bin/env bash
python -c "from app.core.database import Base, engine; import app.models; Base.metadata.create_all(bind=engine)"

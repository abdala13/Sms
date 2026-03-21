#!/usr/bin/env bash
celery -A app.tasks.celery_app.celery_app worker --loglevel=INFO -Q celery

from __future__ import annotations

import asyncio
import random
from copy import deepcopy
from datetime import datetime
from time import perf_counter
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.run import Run, RunEvent, RunItem
from app.models.script import Script
from app.services.challenge_detector import ChallengeDetectorService
from app.services.failure_policy import classify_error
from app.services.safety_guard import validate_target_url


def _render_value(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        for key, replacement in context.items():
            value = value.replace(f'{{{{{key}}}}}', replacement)
        return value
    if isinstance(value, list):
        return [_render_value(v, context) for v in value]
    if isinstance(value, dict):
        return {k: _render_value(v, context) for k, v in value.items()}
    return value


def _build_request_definition(definition: dict[str, Any], input_value: str) -> dict[str, Any]:
    data = deepcopy(definition)
    context = {'input': input_value or ''}
    return _render_value(data, context)


async def execute_run(db: Session, run: Run):
    script = db.get(Script, run.script_id)
    settings = run.resolved_settings_snapshot_json or {}
    options = run.runtime_options_snapshot_json or {}
    request_definition = script.request_definition
    validate_target_url(request_definition['url'])
    timeout = int(settings.get('default_timeout_seconds') or get_settings().default_timeout_seconds)
    workers = max(1, min(int(options.get('workers', 1)), get_settings().max_workers_per_run))
    rpm = max(1, int(options.get('max_requests_per_minute') or settings.get('rate_limit_per_minute') or 60))
    delay_ms = max(0, int(options.get('delay_ms', 0)))
    processing_mode = options.get('processing_mode', 'sequential')
    continue_on_error = bool(options.get('continue_on_error', True))
    retry_count = max(0, int(settings.get('retry_count', 0)))
    failure_ratio_limit = options.get('max_failure_ratio')
    if failure_ratio_limit is not None:
        try:
            failure_ratio_limit = float(failure_ratio_limit)
        except Exception:
            failure_ratio_limit = None
    interval = 60 / rpm
    semaphore = asyncio.Semaphore(workers)
    threshold = int(options.get('repeated_failure_threshold', settings.get('repeated_failure_threshold', 5)))
    last_request_at = 0.0
    rate_lock = asyncio.Lock()
    failures_in_row = 0

    items = list(run.items)
    if processing_mode == 'random':
        random.shuffle(items)

    run.status = 'running'
    run.started_at = datetime.utcnow()
    run.last_activity_at = datetime.utcnow()
    db.add(RunEvent(run_id=run.id, event_type='run_started', message='Run started', details_json={'workers': workers, 'rpm': rpm}))
    db.commit()

    user_agents = settings.get('shared_user_agents_json') or []

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async def process(item: RunItem):
            nonlocal last_request_at, failures_in_row
            if run.stop_requested or run.status in {'paused_verification', 'failed', 'stopped'}:
                return
            async with semaphore:
                db.refresh(run)
                if run.stop_requested or run.status in {'paused_verification', 'failed', 'stopped'}:
                    return
                item.started_at = datetime.utcnow()
                item.status = 'running'
                db.commit()
                start = perf_counter()
                exc = None
                status_code = None
                text = ''
                err_type = None
                attempt = 0
                local_definition = _build_request_definition(request_definition, item.input_value)
                headers = local_definition.get('headers') or {}
                if user_agents and options.get('use_shared_user_agents', True) and 'User-Agent' not in headers:
                    headers['User-Agent'] = random.choice(user_agents)
                while attempt <= retry_count:
                    attempt += 1
                    item.attempt_count = attempt
                    async with rate_lock:
                        now = perf_counter()
                        wait = interval - (now - last_request_at)
                        if wait > 0:
                            await asyncio.sleep(wait)
                        if delay_ms:
                            await asyncio.sleep(delay_ms / 1000)
                        last_request_at = perf_counter()
                    try:
                        if options.get('dry_run'):
                            status_code = 0
                            text = 'Dry run only.'
                        else:
                            payload = {}
                            if local_definition.get('json_body') is not None:
                                payload['json'] = local_definition['json_body']
                            elif local_definition.get('form_body') is not None:
                                payload['data'] = local_definition['form_body']
                            elif local_definition.get('raw_body') is not None:
                                payload['content'] = local_definition['raw_body']
                            resp = await client.request(
                                local_definition['method'],
                                local_definition['url'],
                                headers=headers,
                                cookies=local_definition.get('cookies') or {},
                                params=local_definition.get('query_params') or {},
                                **payload,
                            )
                            status_code = resp.status_code
                            text = resp.text[:1200]
                        exc = None
                    except Exception as e:  # noqa: BLE001
                        exc = e
                        text = ''
                    err_type = classify_error(exc, status_code)
                    if err_type in {'network.timeout', 'network.connection', 'http.429', 'http.500', 'http.502', 'http.503', 'http.504'} and attempt <= retry_count:
                        run.retry_count += 1
                        db.add(RunEvent(run_id=run.id, event_type='retry_scheduled', message=f'Retrying item {item.sequence_no}', details_json={'attempt': attempt, 'error_type': err_type}))
                        db.commit()
                        await asyncio.sleep(min(attempt, 5))
                        continue
                    break

                duration_ms = int((perf_counter() - start) * 1000)
                challenge = ChallengeDetectorService.detect(text, headers={})
                if challenge:
                    item.status = 'challenged'
                    item.error_type = challenge['type']
                    item.result_message = 'Challenge detected; manual verification required.'
                    run.failure_count += 1
                    failures_in_row += 1
                    run.status = 'paused_verification'
                    run.stop_reason = 'Challenge detected'
                    db.add(RunEvent(run_id=run.id, event_type='challenge_detected', message=item.result_message, details_json=challenge))
                elif exc is None and (status_code is None or status_code < 400):
                    item.status = 'success'
                    item.result_message = 'Request completed'
                    run.success_count += 1
                    failures_in_row = 0
                    db.add(RunEvent(run_id=run.id, event_type='item_success', message=f'Item {item.sequence_no} completed', details_json={'status_code': status_code}))
                else:
                    item.status = 'failed'
                    item.error_type = err_type
                    item.result_message = str(exc)[:300] if exc else f'HTTP {status_code}'
                    item.technical_details = repr(exc)[:1500] if exc else text[:1500]
                    run.failure_count += 1
                    failures_in_row += 1
                    db.add(RunEvent(run_id=run.id, event_type='item_failed', message=item.result_message, details_json={'error_type': err_type, 'status_code': status_code}))
                    if not continue_on_error:
                        run.stop_requested = 1
                        run.stop_reason = 'Stopped on first error'
                item.http_status_code = status_code
                item.response_excerpt = text
                item.duration_ms = duration_ms
                item.ended_at = datetime.utcnow()
                run.processed_items += 1
                run.progress_percent = round((run.processed_items / max(run.total_items, 1)) * 100, 2)
                run.last_activity_at = datetime.utcnow()

                if options.get('stop_on_repeated_failures', True) and failures_in_row >= threshold:
                    run.status = 'failed'
                    run.stop_reason = f'Repeated failures threshold reached ({threshold})'
                    run.stop_requested = 1
                    db.add(RunEvent(run_id=run.id, event_type='threshold_stop', message=run.stop_reason, details_json={}))

                if failure_ratio_limit is not None and run.processed_items > 0:
                    ratio = run.failure_count / run.processed_items
                    if ratio > failure_ratio_limit:
                        run.status = 'failed'
                        run.stop_reason = f'Failure ratio exceeded ({ratio:.2f} > {failure_ratio_limit:.2f})'
                        run.stop_requested = 1
                        db.add(RunEvent(run_id=run.id, event_type='ratio_stop', message=run.stop_reason, details_json={'ratio': ratio}))
                db.commit()

        await asyncio.gather(*(process(item) for item in items))
    db.refresh(run)
    if run.status == 'running':
        run.status = 'stopped' if run.stop_requested else 'completed'
    elif run.stop_requested and run.status == 'queued':
        run.status = 'stopped'
    run.ended_at = datetime.utcnow()
    run.summary_message = f'Processed {run.processed_items}/{run.total_items}; success={run.success_count}; failed={run.failure_count}; retries={run.retry_count}'
    db.add(RunEvent(run_id=run.id, event_type='run_finished', message=run.summary_message, details_json={'status': run.status}))
    db.commit()

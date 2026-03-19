import os
import re
import sqlite3
import json
import hashlib
import zipfile
from urllib.parse import urlparse, urljoin
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g
import requests
from bs4 import BeautifulSoup

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'data' / 'app.db'
UPLOAD_DIR = BASE_DIR / 'data' / 'downloads'
SCREENSHOT_DIR = BASE_DIR / 'static' / 'screenshots'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-change-me')


# ---------------------- DB ----------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        '''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            input_text TEXT NOT NULL,
            options_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'completed'
        );

        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            input_value TEXT NOT NULL,
            input_type TEXT NOT NULL,
            target_type TEXT NOT NULL,
            resolved_value TEXT,
            status TEXT NOT NULL,
            summary TEXT,
            classification TEXT,
            confidence_label TEXT,
            confidence_score INTEGER DEFAULT 0,
            testable INTEGER DEFAULT 0,
            page_url TEXT,
            evidence_json TEXT,
            details_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS test_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            mode TEXT NOT NULL,
            phone_number TEXT,
            status TEXT NOT NULL,
            message TEXT,
            screenshot_path TEXT,
            output_json TEXT,
            FOREIGN KEY(target_id) REFERENCES targets(id)
        );
        '''
    )
    defaults = {
        'default_phone_number': '',
        'allowed_test_domains': '',
        'default_test_mode': 'detect_only',
        'playwright_headless': 'true',
        'playwright_timeout_ms': '20000',
        'max_pages': '12',
        'crawl_depth': '2',
        'analyze_js': 'true',
    }
    for k, v in defaults.items():
        cur.execute('INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)', (k, v))
    db.commit()
    db.close()


# ---------------------- Settings helpers ----------------------
def get_setting(key, default=''):
    row = get_db().execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else default


def set_setting(key, value):
    get_db().execute('INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))
    get_db().commit()


def all_settings():
    rows = get_db().execute('SELECT key, value FROM settings').fetchall()
    return {r['key']: r['value'] for r in rows}


# ---------------------- Parsing ----------------------
def detect_input_type(value: str) -> str:
    v = value.strip()
    lv = v.lower()
    if not v:
        return 'unknown'
    if lv.endswith('.apk') and lv.startswith(('http://', 'https://')):
        return 'apk_direct'
    if 'play.google.com/store/apps/details' in lv:
        return 'play_store'
    if lv.startswith(('http://', 'https://')):
        return 'url'
    if '.' in v and ' ' not in v and '/' not in v:
        return 'domain'
    return 'sender'


def normalize_targets(raw_text: str):
    seen = set()
    result = []
    for line in raw_text.splitlines():
        item = line.strip()
        if not item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append({'input_value': item, 'input_type': detect_input_type(item)})
    return result


# ---------------------- Analysis rules ----------------------
PHONE_PATTERNS = [
    (r'phone number|mobile number|add phone|verify your phone|verify phone|phone verification', 18),
    (r'otp|one[- ]time password|verification code|confirm code|send code|resend code|sms code', 18),
    (r'two[- ]factor|2fa|multi[- ]factor|mfa', 16),
    (r'recovery phone|account recovery', 12),
]

URL_PRIORITY = ['signup', 'register', 'security', 'settings', 'account', 'phone', 'mobile', 'verify', 'auth', 'login']


def score_text(text: str):
    score = 0
    evidence = []
    lower = text.lower()
    for pat, pts in PHONE_PATTERNS:
        if re.search(pat, lower, flags=re.I):
            score += pts
            evidence.append(f"Matched text pattern: {pat}")
    return score, evidence


def infer_classification(evidence_text: str, url: str):
    t = evidence_text.lower() + ' ' + url.lower()
    if any(k in t for k in ['two-factor', '2fa', 'mfa']):
        return '2FA / Security'
    if any(k in t for k in ['recovery phone', 'account recovery']):
        return 'Recovery Flow'
    if any(k in t for k in ['add phone', 'settings', 'security']) and any(k in t for k in ['verify', 'sms', 'otp', 'code']):
        return 'Post-Signup Phone Binding'
    if any(k in t for k in ['signup', 'register']) and any(k in t for k in ['verify', 'sms', 'otp', 'code']):
        return 'Signup Flow'
    if any(k in t for k in ['otp', 'verification code', 'confirm code']):
        return 'OTP Entry'
    if any(k in t for k in ['verify', 'send code', 'sms']):
        return 'SMS Verification'
    if 'phone' in t or 'mobile' in t:
        return 'Phone Collection'
    return 'Weak Signal'


def label_confidence(score: int):
    if score >= 70:
        return 'Strong'
    if score >= 40:
        return 'Possible'
    if score >= 18:
        return 'Weak'
    return 'No clear evidence'


# ---------------------- Web analysis ----------------------
def resolver_from_sender(name: str):
    slug = re.sub(r'[^a-z0-9]+', '', name.lower())
    if not slug:
        return None
    return f'https://www.{slug}.com'


def same_domain(a, b):
    try:
        ha = urlparse(a).hostname or ''
        hb = urlparse(b).hostname or ''
        return ha == hb
    except Exception:
        return False


def fetch(url):
    try:
        return requests.get(url, timeout=12, headers={'User-Agent': 'SentinelVerify/1.0'}, allow_redirects=True)
    except Exception:
        return None


def extract_candidate_links(base_url, soup):
    links = []
    for a in soup.find_all('a', href=True):
        href = urljoin(base_url, a['href'])
        if not href.startswith(('http://', 'https://')):
            continue
        if not same_domain(base_url, href):
            continue
        if href not in links:
            links.append(href)
    links.sort(key=lambda u: sum(1 for p in URL_PRIORITY if p in u.lower()), reverse=True)
    return links


def analyze_page(url, html, analyze_js=True):
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text(' ', strip=True)
    title = soup.title.get_text(' ', strip=True) if soup.title else ''

    score, evidence = score_text(text + ' ' + title)
    details = {
        'title': title,
        'phone_input_found': False,
        'action_button_found': False,
        'js_hints': [],
        'matched_inputs': [],
        'matched_buttons': []
    }

    for inp in soup.find_all('input'):
        attrs = ' '.join([
            inp.attrs.get('type', ''), inp.attrs.get('name', ''), inp.attrs.get('id', ''), inp.attrs.get('placeholder', '')
        ]).lower()
        if any(k in attrs for k in ['tel', 'phone', 'mobile']):
            score += 22
            details['phone_input_found'] = True
            details['matched_inputs'].append(attrs[:120])
            evidence.append('Detected phone/mobile input field')
            break

    button_texts = []
    for b in soup.find_all(['button', 'input', 'a']):
        txt = (b.get_text(' ', strip=True) or b.attrs.get('value', '') or '').lower()
        if txt:
            button_texts.append(txt)
        if any(k in txt for k in ['send code', 'verify', 'continue', 'next', 'send otp']):
            score += 18
            details['action_button_found'] = True
            details['matched_buttons'].append(txt[:120])
            evidence.append(f'Found action button/link: {txt[:50]}')
            break

    if analyze_js:
        for s in soup.find_all('script'):
            block = (s.get_text(' ', strip=True) or '')[:4000].lower()
            for k in ['sendotp', 'verifyotp', 'sms', 'twilio', 'firebase', 'phoneauthprovider', 'signinwithphonenumber']:
                if k in block:
                    score += 12
                    details['js_hints'].append(k)
                    evidence.append(f'JS hint found: {k}')
        details['js_hints'] = sorted(set(details['js_hints']))

    classification = infer_classification(text + ' ' + title + ' ' + ' '.join(button_texts), url)
    confidence = label_confidence(score)
    summary = f'{classification} detected on page analysis.' if confidence != 'No clear evidence' else 'No strong verification evidence found.'
    return {
        'url': url,
        'title': title,
        'score': score,
        'classification': classification,
        'confidence': confidence,
        'summary': summary,
        'evidence': sorted(set(evidence)),
        'details': details,
    }


def analyze_web_target(target_value, input_type, max_pages=12, crawl_depth=2, analyze_js=True):
    if input_type == 'sender':
        root = resolver_from_sender(target_value)
    elif input_type == 'domain':
        root = 'https://' + target_value
    else:
        root = target_value

    visited = set()
    queue = [(root, 0)]
    findings = []
    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > crawl_depth:
            continue
        visited.add(url)
        resp = fetch(url)
        if not resp or not resp.ok or 'text/html' not in resp.headers.get('content-type', ''):
            continue
        finding = analyze_page(resp.url, resp.text, analyze_js=analyze_js)
        findings.append(finding)
        soup = BeautifulSoup(resp.text, 'html.parser')
        if depth < crawl_depth:
            for nxt in extract_candidate_links(resp.url, soup):
                if nxt not in visited and len(queue) + len(visited) < max_pages * 3:
                    queue.append((nxt, depth + 1))

    if not findings:
        return {
            'resolved_value': root,
            'classification': 'Weak Signal',
            'confidence': 'No clear evidence',
            'confidence_score': 0,
            'summary': 'Could not fetch analyzable HTML pages.',
            'page_url': root,
            'evidence': ['No analyzable HTML response found.'],
            'details': {'pages': []},
            'testable': False,
        }

    findings.sort(key=lambda x: x['score'], reverse=True)
    best = findings[0]
    resolved_host = urlparse(best['url']).hostname or ''
    allowed_domains = [d.strip().lower() for d in get_setting('allowed_test_domains', '').splitlines() if d.strip()]
    is_allowed = any(resolved_host == d or resolved_host.endswith('.' + d) for d in allowed_domains)
    testable = is_allowed and best['details'].get('phone_input_found') and best['details'].get('action_button_found')
    return {
        'resolved_value': root,
        'classification': best['classification'],
        'confidence': best['confidence'],
        'confidence_score': int(best['score']),
        'summary': best['summary'],
        'page_url': best['url'],
        'evidence': best['evidence'],
        'details': {'pages': findings[:8], 'best': best},
        'testable': bool(testable),
    }


# ---------------------- App analysis ----------------------
def analyze_play_store(url):
    resp = fetch(url)
    if not resp or not resp.ok:
        return {
            'classification': 'Weak Signal', 'confidence': 'Weak', 'confidence_score': 15,
            'summary': 'Could not read Play Store page.', 'evidence': ['Play Store page fetch failed.'],
            'details': {'url': url}, 'resolved_value': url, 'page_url': url, 'testable': False
        }
    soup = BeautifulSoup(resp.text, 'html.parser')
    text = soup.get_text(' ', strip=True)
    package_match = re.search(r'[?&]id=([A-Za-z0-9._]+)', url)
    package_name = package_match.group(1) if package_match else ''
    score, evidence = score_text(text)
    classification = infer_classification(text, url)
    confidence = label_confidence(score)
    return {
        'classification': classification if classification != 'Weak Signal' else 'Phone-based Login',
        'confidence': confidence,
        'confidence_score': score,
        'summary': 'Play Store metadata analyzed for verification clues.',
        'evidence': evidence or ['App metadata page analyzed.'],
        'details': {'package_name': package_name, 'page_text_excerpt': text[:1500]},
        'resolved_value': url,
        'page_url': url,
        'testable': False,
    }


def analyze_apk_direct(url):
    file_hash = hashlib.sha1(url.encode()).hexdigest()[:12]
    apk_path = UPLOAD_DIR / f'{file_hash}.apk'
    if not apk_path.exists():
        resp = fetch(url)
        if not resp or not resp.ok:
            return {
                'classification': 'Weak Signal', 'confidence': 'Weak', 'confidence_score': 10,
                'summary': 'Could not download APK.', 'evidence': ['APK download failed.'],
                'details': {'url': url}, 'resolved_value': url, 'page_url': url, 'testable': False
            }
        apk_path.write_bytes(resp.content)

    names = []
    strings_found = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            names = zf.namelist()[:300]
            for name in names:
                lname = name.lower()
                if any(k in lname for k in ['phone', 'otp', 'verify', 'sms', 'auth', 'login']):
                    strings_found.append(name)
            sample_files = [n for n in names if n.endswith(('.xml', '.txt', '.json'))][:12]
            for sf in sample_files:
                try:
                    data = zf.read(sf)[:120000].decode('utf-8', errors='ignore').lower()
                except Exception:
                    continue
                for keyword in ['phone', 'mobile', 'otp', 'verify', 'sms', 'code', '2fa']:
                    if keyword in data:
                        strings_found.append(f'{sf}: contains {keyword}')
    except Exception:
        strings_found.append('APK opened partially or format inspection limited.')

    evidence = sorted(set(strings_found))[:20] or ['APK structure analyzed.']
    score = min(20 + len(evidence) * 4, 88)
    classification = 'Phone-based Login' if any('phone' in e.lower() for e in evidence) else 'Weak Signal'
    if any('otp' in e.lower() or 'sms' in e.lower() or 'verify' in e.lower() for e in evidence):
        classification = 'SMS Verification'
    return {
        'classification': classification,
        'confidence': label_confidence(score),
        'confidence_score': score,
        'summary': 'Static APK inspection completed.',
        'evidence': evidence,
        'details': {'apk_path': str(apk_path), 'entries_sample': names[:40]},
        'resolved_value': url,
        'page_url': url,
        'testable': False,
    }


# ---------------------- Testing ----------------------
def run_playwright_test(url, phone_number, mode='detect_only'):
    screenshot_name = f"test_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{hashlib.md5(url.encode()).hexdigest()[:8]}.png"
    screenshot_path = SCREENSHOT_DIR / screenshot_name
    output = {
        'ok': False,
        'mode': mode,
        'phone_input_found': False,
        'action_button_found': False,
        'clicked': False,
        'message': '',
    }

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        output['message'] = 'Playwright is not installed in the current environment.'
        return output, None

    headless = get_setting('playwright_headless', 'true').lower() == 'true'
    timeout_ms = int(get_setting('playwright_timeout_ms', '20000') or '20000')
    phone_selectors = [
        'input[type="tel"]',
        'input[name*="phone" i]',
        'input[id*="phone" i]',
        'input[placeholder*="phone" i]',
        'input[name*="mobile" i]',
        'input[id*="mobile" i]',
    ]
    button_selectors = [
        'button:has-text("Send code")',
        'button:has-text("Verify")',
        'button:has-text("Continue")',
        'button:has-text("Next")',
        'button:has-text("Send OTP")',
        'button:has-text("Send")',
        'input[type="submit"]',
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()
        try:
            page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)
            phone_input = None
            for sel in phone_selectors:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    phone_input = loc.first
                    output['phone_input_found'] = True
                    break

            action_button = None
            for sel in button_selectors:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    action_button = loc.first
                    output['action_button_found'] = True
                    break

            if mode in ('fill_only', 'test_send') and phone_input and phone_number:
                phone_input.fill(phone_number)

            if mode == 'test_send' and action_button:
                action_button.click()
                output['clicked'] = True
                page.wait_for_timeout(2500)

            page.screenshot(path=str(screenshot_path), full_page=True)
            body_text = page.locator('body').inner_text()[:1500]
            output['message'] = body_text[:300] or 'Page loaded.'
            output['ok'] = output['phone_input_found'] or output['action_button_found']
        except Exception as e:
            output['message'] = str(e)
        finally:
            browser.close()

    return output, f'screenshots/{screenshot_name}'


# ---------------------- Core actions ----------------------
def create_scan(input_text, options):
    db = get_db()
    now = datetime.utcnow().isoformat()
    cur = db.execute(
        'INSERT INTO scans(created_at, input_text, options_json, status) VALUES (?, ?, ?, ?)',
        (now, input_text, json.dumps(options), 'completed')
    )
    scan_id = cur.lastrowid
    db.commit()
    return scan_id


def store_target(scan_id, item, result):
    db = get_db()
    db.execute(
        '''INSERT INTO targets(
            scan_id, input_value, input_type, target_type, resolved_value, status, summary,
            classification, confidence_label, confidence_score, testable, page_url,
            evidence_json, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            scan_id,
            item['input_value'],
            item['input_type'],
            'app' if item['input_type'] in ('apk_direct', 'play_store') else 'web',
            result.get('resolved_value'),
            'done',
            result.get('summary'),
            result.get('classification'),
            result.get('confidence'),
            result.get('confidence_score', 0),
            1 if result.get('testable') else 0,
            result.get('page_url'),
            json.dumps(result.get('evidence', []), ensure_ascii=False),
            json.dumps(result.get('details', {}), ensure_ascii=False),
            datetime.utcnow().isoformat(),
        )
    )
    db.commit()


def process_scan(input_text, options):
    scan_id = create_scan(input_text, options)
    items = normalize_targets(input_text)
    max_pages = int(options.get('max_pages') or get_setting('max_pages', '12'))
    crawl_depth = int(options.get('crawl_depth') or get_setting('crawl_depth', '2'))
    analyze_js = str(options.get('analyze_js', 'true')).lower() == 'true'
    for item in items:
        if item['input_type'] in ('apk_direct', 'play_store'):
            if item['input_type'] == 'apk_direct':
                result = analyze_apk_direct(item['input_value'])
            else:
                result = analyze_play_store(item['input_value'])
        else:
            result = analyze_web_target(item['input_value'], item['input_type'], max_pages=max_pages, crawl_depth=crawl_depth, analyze_js=analyze_js)
        store_target(scan_id, item, result)
    return scan_id


# ---------------------- Routes ----------------------
@app.route('/')
def dashboard():
    db = get_db()
    stats = {
        'scans': db.execute('SELECT COUNT(*) c FROM scans').fetchone()['c'],
        'targets': db.execute('SELECT COUNT(*) c FROM targets').fetchone()['c'],
        'web_results': db.execute("SELECT COUNT(*) c FROM targets WHERE target_type='web'").fetchone()['c'],
        'app_results': db.execute("SELECT COUNT(*) c FROM targets WHERE target_type='app'").fetchone()['c'],
        'testable': db.execute('SELECT COUNT(*) c FROM targets WHERE testable=1').fetchone()['c'],
        'tests': db.execute('SELECT COUNT(*) c FROM test_runs').fetchone()['c'],
    }
    recent_targets = db.execute('SELECT * FROM targets ORDER BY id DESC LIMIT 8').fetchall()
    recent_tests = db.execute('SELECT * FROM test_runs ORDER BY id DESC LIMIT 6').fetchall()
    return render_template('dashboard.html', stats=stats, recent_targets=recent_targets, recent_tests=recent_tests)


@app.route('/scan/new', methods=['GET', 'POST'])
def new_scan():
    settings = all_settings()
    if request.method == 'POST':
        input_text = request.form.get('targets', '').strip()
        if not input_text:
            flash('أدخل هدفًا واحدًا على الأقل.', 'danger')
            return redirect(url_for('new_scan'))
        options = {
            'max_pages': request.form.get('max_pages', settings.get('max_pages', '12')),
            'crawl_depth': request.form.get('crawl_depth', settings.get('crawl_depth', '2')),
            'analyze_js': 'true' if request.form.get('analyze_js') else 'false',
        }
        scan_id = process_scan(input_text, options)
        flash('تم تنفيذ الفحص بنجاح.', 'success')
        return redirect(url_for('scan_results', scan_id=scan_id))
    return render_template('new_scan.html', settings=settings)


@app.route('/scan/<int:scan_id>/results')
def scan_results(scan_id):
    db = get_db()
    scan = db.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    targets = db.execute('SELECT * FROM targets WHERE scan_id=? ORDER BY confidence_score DESC, id DESC', (scan_id,)).fetchall()
    return render_template('results.html', scan=scan, targets=targets, json=json)


@app.route('/target/<int:target_id>')
def target_detail(target_id):
    db = get_db()
    target = db.execute('SELECT * FROM targets WHERE id=?', (target_id,)).fetchone()
    tests = db.execute('SELECT * FROM test_runs WHERE target_id=? ORDER BY id DESC', (target_id,)).fetchall()
    if not target:
        flash('النتيجة غير موجودة.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('target_detail.html', target=target, tests=tests, json=json)


@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    if request.method == 'POST':
        keys = ['default_phone_number', 'allowed_test_domains', 'default_test_mode', 'playwright_headless', 'playwright_timeout_ms', 'max_pages', 'crawl_depth']
        for k in keys:
            set_setting(k, request.form.get(k, ''))
        set_setting('analyze_js', 'true' if request.form.get('analyze_js') else 'false')
        flash('تم حفظ الإعدادات.', 'success')
        return redirect(url_for('settings_page'))
    return render_template('settings.html', settings=all_settings())


@app.route('/target/<int:target_id>/test', methods=['POST'])
def run_test(target_id):
    db = get_db()
    target = db.execute('SELECT * FROM targets WHERE id=?', (target_id,)).fetchone()
    if not target:
        flash('النتيجة غير موجودة.', 'danger')
        return redirect(url_for('dashboard'))

    phone_number = request.form.get('phone_number', '').strip() or get_setting('default_phone_number', '')
    mode = request.form.get('mode', get_setting('default_test_mode', 'detect_only'))
    if target['target_type'] != 'web':
        flash('الاختبار مخصص لنتائج الويب فقط.', 'danger')
        return redirect(url_for('target_detail', target_id=target_id))

    output, screenshot_rel = run_playwright_test(target['page_url'], phone_number, mode)
    status = 'success' if output.get('ok') else 'failed'
    db.execute(
        'INSERT INTO test_runs(target_id, created_at, mode, phone_number, status, message, screenshot_path, output_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (target_id, datetime.utcnow().isoformat(), mode, phone_number, status, output.get('message', ''), screenshot_rel, json.dumps(output, ensure_ascii=False))
    )
    db.commit()
    flash('تم تنفيذ الاختبار.' if output.get('ok') else 'تم حفظ نتيجة الاختبار، لكن لم يظهر نجاح واضح.', 'success' if output.get('ok') else 'warning')
    return redirect(url_for('target_detail', target_id=target_id))


@app.template_filter('fromjson')
def fromjson_filter(value):
    try:
        return json.loads(value or '[]')
    except Exception:
        return []


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '10000')), debug=False)

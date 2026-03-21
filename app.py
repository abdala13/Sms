import os, re, io, json, sqlite3, zipfile, threading
from collections import deque
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from flask import Flask, g, redirect, render_template, request, url_for, flash, jsonify

APP_TITLE = 'Sentinel Verify Platform'
DB_PATH = os.environ.get('SQLITE_PATH', 'sentinel_verify.db')
HEADERS = {'User-Agent': os.environ.get('USER_AGENT', 'SentinelVerify/2.0')}
PORT = int(os.environ.get('PORT', '10000'))
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

# ---------- DB ----------
def connect_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db

def get_db():
    if 'db' not in g:
        g.db = connect_db()
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = connect_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY CHECK (id=1),
        default_phone TEXT DEFAULT '',
        allowed_domains TEXT DEFAULT '',
        default_test_mode TEXT DEFAULT 'detect_only',
        max_pages INTEGER DEFAULT 15,
        crawl_depth INTEGER DEFAULT 2,
        analyze_js INTEGER DEFAULT 1,
        confidence_threshold INTEGER DEFAULT 45,
        min_save_confidence INTEGER DEFAULT 20
    );
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        raw_input TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        total_targets INTEGER DEFAULT 0,
        completed_targets INTEGER DEFAULT 0,
        current_target TEXT DEFAULT '',
        notes TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        target_label TEXT NOT NULL,
        target_type TEXT NOT NULL,
        resolved_url TEXT DEFAULT '',
        page_url TEXT DEFAULT '',
        classification TEXT DEFAULT 'Weak Signal',
        confidence INTEGER DEFAULT 0,
        phone_score INTEGER DEFAULT 0,
        sms_score INTEGER DEFAULT 0,
        otp_score INTEGER DEFAULT 0,
        signup_score INTEGER DEFAULT 0,
        post_signup_score INTEGER DEFAULT 0,
        security_score INTEGER DEFAULT 0,
        recovery_score INTEGER DEFAULT 0,
        testable INTEGER DEFAULT 0,
        evidence_json TEXT DEFAULT '[]',
        page_title TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        summary TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS test_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        run_mode TEXT NOT NULL,
        phone_number TEXT DEFAULT '',
        status TEXT NOT NULL,
        message TEXT DEFAULT '',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS crawl_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        target_label TEXT DEFAULT '',
        url TEXT DEFAULT '',
        status TEXT DEFAULT '',
        created_at TEXT NOT NULL
    );
    ''')
    db.execute('INSERT OR IGNORE INTO settings (id) VALUES (1)')
    db.commit(); db.close()

def now_iso():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

def get_settings(db=None):
    db = db or get_db()
    return dict(db.execute('SELECT * FROM settings WHERE id=1').fetchone())

def save_settings(form):
    db = get_db()
    db.execute("UPDATE settings SET default_phone=?, allowed_domains=?, default_test_mode=?, max_pages=?, crawl_depth=?, analyze_js=?, confidence_threshold=?, min_save_confidence=? WHERE id=1",(
        form.get('default_phone','').strip(),
        form.get('allowed_domains','').strip(),
        form.get('default_test_mode','detect_only'),
        int(form.get('max_pages',15) or 15),
        int(form.get('crawl_depth',2) or 2),
        1 if form.get('analyze_js') else 0,
        int(form.get('confidence_threshold',45) or 45),
        int(form.get('min_save_confidence',20) or 20),
    ))
    db.commit()

def log_event(db, scan_id, target_label, url, status):
    db.execute('INSERT INTO crawl_events (scan_id, target_label, url, status, created_at) VALUES (?, ?, ?, ?, ?)', (scan_id, target_label, url, status, now_iso()))
    db.commit()

def safe_get(url, timeout=15):
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def normalize_domain(v):
    v = v.strip().lower()
    return re.sub(r'^https?://', '', v).split('/')[0]

def domain_allowed(url, allowed_domains_text):
    host = (urlparse(url).hostname or '').lower()
    allowed = [normalize_domain(x) for x in allowed_domains_text.splitlines() if x.strip()]
    return any(host == d or host.endswith('.'+d) for d in allowed)

def slugify(text):
    return re.sub(r'[^a-z0-9]+', '-', text.strip().lower()).strip('-')

def detect_input_type(value):
    v = value.strip(); lv = v.lower()
    if lv.endswith('.apk') and lv.startswith('http'): return 'apk_direct'
    if 'play.google.com/store/apps/details' in lv: return 'play_store'
    if lv.startswith('http://') or lv.startswith('https://'): return 'url'
    if '.' in v and ' ' not in v and '/' not in v: return 'domain'
    return 'sender'

def resolve_target(value):
    t = detect_input_type(value)
    if t == 'url': return {'type':'web','url':value}
    if t == 'domain': return {'type':'web','url':f'https://{value}'}
    if t == 'sender':
        slug = slugify(value)
        return {'type':'web','url':f'https://www.{slug}.com' if slug else ''}
    if t in ('play_store','apk_direct'): return {'type':'app','url':value}
    return {'type':'unknown','url':value}

PRIORITY = ['signup','register','login','auth','verify','otp','phone','mobile','account','security','settings','recovery','2fa']

def crawl_site(start_url, max_pages=15, depth_limit=2, on_event=None):
    q = deque([(start_url,0)]); visited, pages = set(), []
    start_host = urlparse(start_url).hostname or ''
    while q and len(pages) < max_pages:
        url, depth = q.popleft()
        if url in visited or depth > depth_limit: continue
        visited.add(url)
        if on_event: on_event(url, 'fetching')
        r = safe_get(url)
        if not r or not r.ok or 'text/html' not in r.headers.get('content-type',''):
            if on_event: on_event(url, 'skipped')
            continue
        html = r.text[:300000]
        pages.append({'url':r.url,'html':html})
        if on_event: on_event(r.url, 'visited')
        if depth >= depth_limit: continue
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            href = a.get('href','').strip()
            if href.startswith('#') or href.startswith('mailto:') or href.startswith('javascript:'): continue
            full = urljoin(r.url, href); p = urlparse(full)
            if p.scheme not in ('http','https') or (p.hostname or '') != start_host: continue
            links.append(f'{p.scheme}://{p.netloc}{p.path}')
        links = sorted(set(links), key=lambda u: sum(10 for x in PRIORITY if x in u.lower()), reverse=True)
        for link in links[:25]:
            if link not in visited: q.append((link, depth+1))
    return pages

def analyze_html_page(page_url, html, analyze_js=True):
    soup = BeautifulSoup(html, 'html.parser'); lower = html.lower(); title = soup.title.get_text(' ', strip=True) if soup.title else ''
    evidence = []; scores = dict(phone_score=0,sms_score=0,otp_score=0,signup_score=0,post_signup_score=0,security_score=0,recovery_score=0)
    phone_input_found = False; action_button_found = False
    for inp in soup.find_all('input'):
        attrs = ' '.join([str(inp.get('type','')), str(inp.get('name','')), str(inp.get('id','')), str(inp.get('placeholder',''))]).lower()
        if any(k in attrs for k in ['tel','phone','mobile']):
            phone_input_found = True; scores['phone_score'] += 30; evidence.append('Found phone-like input field')
        if any(k in attrs for k in ['otp','code','verification']):
            scores['otp_score'] += 20; evidence.append('Found OTP/code-like input field')
    joined = ' | '.join([(b.get_text(' ', strip=True) or b.get('value','') or '').strip().lower() for b in soup.find_all(['button','input']) if (b.get_text(' ', strip=True) or b.get('value','') or '').strip()])
    if re.search(r'send code|verify|continue|next|resend code|send otp|send sms|send', joined, re.I):
        action_button_found = True; scores['sms_score'] += 20; evidence.append('Found action button related to sending/verifying code')
    for token, weight, bucket in [('phone number',10,'phone_score'),('mobile number',10,'phone_score'),('add phone',10,'phone_score'),('verify phone',12,'phone_score'),('send code',12,'sms_score'),('verification code',12,'sms_score'),('we sent you a code',12,'sms_score'),('otp',12,'sms_score'),('text message',10,'sms_score'),('verify by sms',12,'sms_score'),('two-factor',15,'security_score'),('2fa',15,'security_score'),('multi-factor',15,'security_score'),('security settings',15,'security_score'),('recovery phone',15,'recovery_score'),('account recovery',15,'recovery_score')]:
        if token in lower:
            scores[bucket] += weight; evidence.append(f'Matched clue: {token}')
    low_url = page_url.lower()
    if any(x in low_url for x in ['signup','register']): scores['signup_score'] += 18; evidence.append('URL suggests signup/register flow')
    if any(x in low_url for x in ['settings','security','account']): scores['post_signup_score'] += 16; evidence.append('URL suggests post-signup/account flow')
    if any(x in low_url for x in ['verify','otp','phone','mobile']): scores['sms_score'] += 10; evidence.append('URL suggests verification/phone flow')
    if analyze_js:
        for s in soup.find_all('script', src=True)[:5]:
            src = urljoin(page_url, s.get('src','')); r = safe_get(src, timeout=10)
            if not r or not r.ok: continue
            js = r.text[:120000].lower()
            for token, weight, bucket, msg in [('sendotp',12,'sms_score','JS contains sendOtp-like token'),('verifyotp',12,'sms_score','JS contains verifyOtp-like token'),('twilio',16,'sms_score','JS mentions Twilio'),('firebase',10,'sms_score','JS mentions Firebase'),('phoneauthprovider',18,'phone_score','JS mentions PhoneAuthProvider')]:
                if token in js: scores[bucket] += weight; evidence.append(msg)
    confidence = min(100, scores['phone_score'] + scores['sms_score'] + scores['otp_score']//2 + scores['signup_score']//2 + scores['post_signup_score']//2 + scores['security_score']//2 + scores['recovery_score']//2)
    classification = 'Weak Signal'; summary = 'No clear phone/SMS evidence found.'
    if scores['security_score'] >= 20 and scores['sms_score'] >= 20: classification='2FA / Security'; summary='Likely uses phone/SMS inside security settings or 2FA.'
    elif scores['signup_score'] >= 15 and scores['phone_score'] >= 25 and scores['sms_score'] >= 20: classification='Signup Flow'; summary='Likely requests phone verification during signup.'
    elif scores['post_signup_score'] >= 15 and scores['phone_score'] >= 25: classification='Post-Signup Phone Binding'; summary='Likely adds or verifies phone after account creation.'
    elif scores['sms_score'] >= 30 and scores['phone_score'] >= 20: classification='SMS Verification'; summary='Likely sends a code by SMS or asks for SMS verification.'
    elif scores['otp_score'] >= 20: classification='OTP Entry'; summary='Likely expects a verification code or OTP.'
    elif scores['recovery_score'] >= 20: classification='Recovery Flow'; summary='Likely uses phone number in account recovery.'
    elif scores['phone_score'] >= 20: classification='Phone Collection'; summary='Likely collects a phone number, but SMS sending is less clear.'
    return {'page_title':title,'classification':classification,'confidence':confidence,'evidence':list(dict.fromkeys(evidence))[:16],'summary':summary,'phone_input_found':phone_input_found,'action_button_found':action_button_found,'scores':scores}

def analyze_web_target(label, url, settings, scan_id, db):
    findings = []
    pages = crawl_site(url, int(settings.get('max_pages',15)), int(settings.get('crawl_depth',2)), on_event=lambda u, st: log_event(db, scan_id, label, u, st))
    for page in pages:
        analysis = analyze_html_page(page['url'], page['html'], bool(settings.get('analyze_js',1)))
        if analysis['confidence'] < int(settings.get('min_save_confidence',20)): continue
        testable = analysis['phone_input_found'] and analysis['action_button_found'] and domain_allowed(page['url'], settings.get('allowed_domains','')) and analysis['confidence'] >= int(settings.get('confidence_threshold',45))
        findings.append({'target_label':label,'target_type':'web','resolved_url':url,'page_url':page['url'],'classification':analysis['classification'],'confidence':analysis['confidence'],'page_title':analysis['page_title'],'summary':analysis['summary'],'testable':1 if testable else 0,'evidence_json':json.dumps(analysis['evidence'], ensure_ascii=False), **analysis['scores']})
    findings.sort(key=lambda x:(x['confidence'], x['testable']), reverse=True)
    return findings[:24]

def analyze_play_store(url):
    r = safe_get(url)
    if not r or not r.ok: return []
    html = r.text[:250000].lower(); score, evidence = 0, []
    for token, weight in [('phone number',25),('verification code',20),('we will send',15),('sms',12),('otp',18),('verify',12),('2fa',10)]:
        if token in html: score += weight; evidence.append(f"Play Store text includes '{token}'")
    m = re.search(r'[?&]id=([a-zA-Z0-9._]+)', url); package = m.group(1) if m else ''
    if package: evidence.append(f'Detected package: {package}')
    if score < 20: return []
    classification = 'Phone-based Login' if score >= 45 else 'SMS Verification' if score >= 25 else 'Phone Collection'
    return [{'target_label':package or url,'target_type':'app','resolved_url':url,'page_url':url,'classification':classification,'confidence':min(score,100),'page_title':'Google Play','summary':'App metadata suggests phone/SMS verification behavior.','testable':0,'evidence_json':json.dumps(evidence, ensure_ascii=False),'phone_score':score,'sms_score':score,'otp_score':0,'signup_score':0,'post_signup_score':0,'security_score':0,'recovery_score':0}]

def analyze_direct_apk(url):
    evidence = ['Detected direct APK link']; confidence = 10
    if any(x in url.lower() for x in ['phone','otp','sms','verify','auth']): confidence += 20; evidence.append('APK URL contains auth/phone clues')
    if confidence < 20: return []
    classification = 'SMS Verification' if confidence >= 45 else 'Phone Collection'
    return [{'target_label':url.split('/')[-1] or 'APK','target_type':'app','resolved_url':url,'page_url':url,'classification':classification,'confidence':min(confidence,100),'page_title':url.split('/')[-1] or 'APK','summary':'Direct APK link analyzed with lightweight static hints.','testable':0,'evidence_json':json.dumps(evidence, ensure_ascii=False),'phone_score':confidence,'sms_score':confidence//2,'otp_score':0,'signup_score':0,'post_signup_score':0,'security_score':0,'recovery_score':0}]

def insert_findings(db, scan_id, findings):
    for f in findings:
        db.execute("INSERT INTO findings (scan_id,target_label,target_type,resolved_url,page_url,classification,confidence,phone_score,sms_score,otp_score,signup_score,post_signup_score,security_score,recovery_score,testable,evidence_json,page_title,created_at,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (scan_id,f['target_label'],f['target_type'],f['resolved_url'],f['page_url'],f['classification'],f['confidence'],f['phone_score'],f['sms_score'],f['otp_score'],f['signup_score'],f['post_signup_score'],f['security_score'],f['recovery_score'],f['testable'],f['evidence_json'],f['page_title'],now_iso(),f['summary']))
    db.commit()

def run_scan_job(scan_id, raw_input):
    db = connect_db()
    try:
        settings = get_settings(db)
        lines, seen = [], set()
        for line in raw_input.splitlines():
            item = line.strip()
            if item and item.lower() not in seen: seen.add(item.lower()); lines.append(item)
        db.execute("UPDATE scans SET status='running', total_targets=? WHERE id=?", (len(lines), scan_id)); db.commit()
        for idx, item in enumerate(lines, start=1):
            db.execute("UPDATE scans SET current_target=?, completed_targets=? WHERE id=?", (item, idx-1, scan_id)); db.commit()
            resolved = resolve_target(item); t = detect_input_type(item); findings = []
            try:
                if resolved['type'] == 'web':
                    log_event(db, scan_id, item, resolved['url'], 'target-start'); findings = analyze_web_target(item, resolved['url'], settings, scan_id, db); log_event(db, scan_id, item, resolved['url'], 'target-finished')
                elif t == 'play_store': log_event(db, scan_id, item, resolved['url'], 'metadata-check'); findings = analyze_play_store(item)
                elif t == 'apk_direct': log_event(db, scan_id, item, resolved['url'], 'apk-check'); findings = analyze_direct_apk(item)
                else: log_event(db, scan_id, item, resolved['url'], 'unsupported')
            except Exception as e:
                log_event(db, scan_id, item, resolved['url'], f'error: {str(e)[:120]}')
            if findings: insert_findings(db, scan_id, findings)
            db.execute("UPDATE scans SET completed_targets=? WHERE id=?", (idx, scan_id)); db.commit()
        count = db.execute('SELECT COUNT(*) c FROM findings WHERE scan_id=?', (scan_id,)).fetchone()['c']
        notes = 'تم الفحص.' if count else 'انتهى الفحص بدون نتائج مطابقة للشروط.'
        db.execute("UPDATE scans SET status='done', current_target='', notes=? WHERE id=?", (notes, scan_id)); db.commit()
    except Exception as e:
        db.execute("UPDATE scans SET status='failed', notes=? WHERE id=?", (str(e)[:240], scan_id)); db.commit()
    finally:
        db.close()

def run_basic_owned_site_test(finding, phone_number, mode):
    if mode == 'detect_only': return ('success','Detection-only mode: page already matched phone/input and action clues.')
    return ('failed','Playwright mode requires installing browser runtime on Render.')

@app.context_processor
def inject_globals(): return {'APP_TITLE': APP_TITLE}

@app.route('/')
def dashboard():
    db = get_db(); stats = {'targets': db.execute('SELECT COUNT(DISTINCT target_label) c FROM findings').fetchone()['c'] or 0,'web_results': db.execute("SELECT COUNT(*) c FROM findings WHERE target_type='web'").fetchone()['c'] or 0,'app_results': db.execute("SELECT COUNT(*) c FROM findings WHERE target_type='app'").fetchone()['c'] or 0,'testable': db.execute('SELECT COUNT(*) c FROM findings WHERE testable=1').fetchone()['c'] or 0,'tests': db.execute('SELECT COUNT(*) c FROM test_runs').fetchone()['c'] or 0}
    recent = db.execute('SELECT * FROM findings ORDER BY id DESC LIMIT 8').fetchall(); scans = db.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 6').fetchall()
    return render_template('dashboard.html', stats=stats, recent=recent, scans=scans)

@app.route('/scan', methods=['GET','POST'])
def scan():
    settings = get_settings()
    if request.method == 'POST':
        raw = request.form.get('targets','').strip()
        if not raw: flash('أدخل هدفًا واحدًا على الأقل.','error'); return redirect(url_for('scan'))
        db = get_db(); cur = db.execute("INSERT INTO scans (created_at, raw_input, status, notes) VALUES (?, ?, 'queued', '')", (now_iso(), raw)); scan_id = cur.lastrowid; db.commit()
        threading.Thread(target=run_scan_job, args=(scan_id, raw), daemon=True).start()
        return redirect(url_for('scan_progress', scan_id=scan_id))
    return render_template('scan.html', settings=settings)

@app.route('/scan/<int:scan_id>/progress')
def scan_progress(scan_id):
    scan = get_db().execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not scan: flash('عملية الفحص غير موجودة.','error'); return redirect(url_for('dashboard'))
    return render_template('progress.html', scan=scan)

@app.route('/scan_status/<int:scan_id>')
def scan_status(scan_id):
    db = get_db(); scan = db.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not scan: return jsonify({'ok': False}), 404
    total = scan['total_targets'] or 0; completed = scan['completed_targets'] or 0
    percent = 5 if scan['status'] == 'queued' else 100 if scan['status'] == 'done' else min(95, int((completed / total) * 100)) if total else 10
    events = db.execute('SELECT target_label, url, status, created_at FROM crawl_events WHERE scan_id=? ORDER BY id DESC LIMIT 60', (scan_id,)).fetchall()
    findings_count = db.execute('SELECT COUNT(*) c FROM findings WHERE scan_id=?', (scan_id,)).fetchone()['c']
    return jsonify({'ok': True,'status': scan['status'],'notes': scan['notes'] or '','current_target': scan['current_target'] or '','completed_targets': completed,'total_targets': total,'percent': percent,'findings_count': findings_count,'events': [dict(e) for e in events]})

@app.route('/results')
def results():
    db = get_db(); scan_id = request.args.get('scan_id', type=int)
    if scan_id:
        findings = db.execute('SELECT * FROM findings WHERE scan_id=? ORDER BY confidence DESC, id DESC', (scan_id,)).fetchall(); scan = db.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    else:
        findings = db.execute('SELECT * FROM findings ORDER BY id DESC LIMIT 100').fetchall(); scan = None
    return render_template('results.html', findings=findings, scan=scan)

@app.route('/finding/<int:finding_id>')
def finding_detail(finding_id):
    db = get_db(); finding = db.execute('SELECT * FROM findings WHERE id=?', (finding_id,)).fetchone()
    if not finding: flash('النتيجة غير موجودة.','error'); return redirect(url_for('results'))
    tests = db.execute('SELECT * FROM test_runs WHERE finding_id=? ORDER BY id DESC', (finding_id,)).fetchall(); evidence = json.loads(finding['evidence_json'] or '[]')
    return render_template('detail.html', finding=finding, evidence=evidence, tests=tests, settings=get_settings())

@app.route('/delete_finding/<int:finding_id>', methods=['POST'])
def delete_finding(finding_id):
    db = get_db(); db.execute('DELETE FROM test_runs WHERE finding_id=?', (finding_id,)); db.execute('DELETE FROM findings WHERE id=?', (finding_id,)); db.commit(); flash('تم حذف النتيجة.','success'); return redirect(request.referrer or url_for('results'))

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    db = get_db(); db.execute('DELETE FROM findings WHERE scan_id=?', (scan_id,)); db.execute('DELETE FROM crawl_events WHERE scan_id=?', (scan_id,)); db.execute('DELETE FROM scans WHERE id=?', (scan_id,)); db.commit(); flash('تم حذف نتائج عملية الفحص.','success'); return redirect(url_for('dashboard'))

@app.route('/delete_all', methods=['POST'])
def delete_all():
    db = get_db(); db.execute('DELETE FROM test_runs'); db.execute('DELETE FROM findings'); db.execute('DELETE FROM crawl_events'); db.execute('DELETE FROM scans'); db.commit(); flash('تم حذف كل النتائج والسجلات.','success'); return redirect(url_for('dashboard'))

@app.route('/settings', methods=['GET','POST'])
def settings_page():
    if request.method == 'POST': save_settings(request.form); flash('تم حفظ الإعدادات.','success'); return redirect(url_for('settings_page'))
    return render_template('settings.html', settings=get_settings())

@app.route('/test/<int:finding_id>', methods=['POST'])
def run_test(finding_id):
    db = get_db(); finding = db.execute('SELECT * FROM findings WHERE id=?', (finding_id,)).fetchone(); settings = get_settings()
    if not finding: flash('النتيجة غير موجودة.','error'); return redirect(url_for('results'))
    if finding['target_type'] != 'web' or not finding['testable']: flash('هذه النتيجة غير مؤهلة للاختبار.','error'); return redirect(url_for('finding_detail', finding_id=finding_id))
    if not domain_allowed(finding['page_url'], settings.get('allowed_domains','')): flash('الدومين غير موجود في قائمة الدومينات المسموح اختبارها.','error'); return redirect(url_for('finding_detail', finding_id=finding_id))
    phone = request.form.get('phone_number','').strip() or settings.get('default_phone',''); mode = request.form.get('run_mode','').strip() or settings.get('default_test_mode','detect_only')
    status, message = run_basic_owned_site_test(finding, phone, mode)
    db.execute('INSERT INTO test_runs (finding_id, run_mode, phone_number, status, message, created_at) VALUES (?, ?, ?, ?, ?, ?)', (finding_id, mode, phone, status, message, now_iso())); db.commit(); flash('تم تنفيذ الاختبار.' if status == 'success' else 'فشل تنفيذ الاختبار.', 'success' if status == 'success' else 'error'); return redirect(url_for('finding_detail', finding_id=finding_id))

if __name__ == '__main__':
    init_db(); app.run(host='0.0.0.0', port=PORT)

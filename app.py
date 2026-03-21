import os, re, json, sqlite3, threading
from collections import deque
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, g, redirect, render_template, request, url_for, flash, jsonify

APP_TITLE = "Sentinel Verify Platform"
DB_PATH = os.environ.get("SQLITE_PATH", "sentinel_verify.db")
PORT = int(os.environ.get("PORT", "10000"))
HEADERS = {"User-Agent": "SentinelVerify/SmartExplorer"}
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")


def connect_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


def get_db():
    if "db" not in g:
        g.db = connect_db()
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def init_db():
    db = connect_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS settings (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          default_phone TEXT DEFAULT '',
          allowed_domains TEXT DEFAULT '',
          max_pages INTEGER DEFAULT 15,
          crawl_depth INTEGER DEFAULT 2,
          confidence_threshold INTEGER DEFAULT 45,
          min_save_confidence INTEGER DEFAULT 20,
          smart_explorer INTEGER DEFAULT 1,
          explorer_click_limit INTEGER DEFAULT 5
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
          testable INTEGER DEFAULT 0,
          evidence_json TEXT DEFAULT '[]',
          page_title TEXT DEFAULT '',
          created_at TEXT NOT NULL,
          summary TEXT DEFAULT '',
          source_mode TEXT DEFAULT 'static'
        );
        CREATE TABLE IF NOT EXISTS crawl_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id INTEGER NOT NULL,
          target_label TEXT DEFAULT '',
          url TEXT DEFAULT '',
          status TEXT DEFAULT '',
          created_at TEXT NOT NULL
        );
        """
    )
    db.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)")
    db.commit()
    db.close()


def get_settings(db=None):
    db = db or get_db()
    return dict(db.execute("SELECT * FROM settings WHERE id=1").fetchone())


def save_settings(form):
    db = get_db()
    db.execute(
        "UPDATE settings SET default_phone=?, allowed_domains=?, max_pages=?, crawl_depth=?, confidence_threshold=?, min_save_confidence=?, smart_explorer=?, explorer_click_limit=? WHERE id=1",
        (
            form.get("default_phone", "").strip(),
            form.get("allowed_domains", "").strip(),
            int(form.get("max_pages", 15) or 15),
            int(form.get("crawl_depth", 2) or 2),
            int(form.get("confidence_threshold", 45) or 45),
            int(form.get("min_save_confidence", 20) or 20),
            1 if form.get("smart_explorer") else 0,
            int(form.get("explorer_click_limit", 5) or 5),
        ),
    )
    db.commit()


def clean_input(v: str) -> str:
    return v.strip().strip("'").strip('"').strip()


def detect_input_type(value: str) -> str:
    v = clean_input(value).lower()
    if v.endswith(".apk") and v.startswith("http"):
        return "apk_direct"
    if "play.google.com/store/apps/details" in v:
        return "play_store"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if "." in v and " " not in v and "/" not in v:
        return "domain"
    return "sender"


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", clean_input(text).lower()).strip("-")


def resolve_target(value: str):
    v = clean_input(value)
    t = detect_input_type(v)
    if t == "url":
        return {"kind": "web", "url": v, "label": v}
    if t == "domain":
        return {"kind": "web", "url": f"https://{v}", "label": v}
    if t == "sender":
        s = slugify(v)
        return {"kind": "web", "url": f"https://www.{s}.com" if s else "", "label": v}
    if t in ("play_store", "apk_direct"):
        return {"kind": "app", "url": v, "label": v}
    return {"kind": "unknown", "url": v, "label": v}


def safe_get(url: str, timeout: int = 15):
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


def log_event(db, scan_id, target_label, url, status):
    db.execute(
        "INSERT INTO crawl_events (scan_id,target_label,url,status,created_at) VALUES (?,?,?,?,?)",
        (scan_id, target_label, url or "", status, now_iso()),
    )
    db.commit()


def normalize_domain(v: str) -> str:
    s = clean_input(v).lower()
    s = re.sub(r"^https?://", "", s)
    return s.split("/")[0]


def domain_allowed(url: str, allowed_text: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    allowed = [normalize_domain(x) for x in allowed_text.splitlines() if x.strip()]
    return any(host == d or host.endswith("." + d) for d in allowed)


PRIORITY = ["signup", "register", "login", "auth", "verify", "otp", "phone", "mobile", "account", "security", "settings", "recovery", "2fa"]
SCAN_THREADS = {}


def static_crawl(start_url, max_pages, depth_limit, on_event=None):
    q = deque([(start_url, 0)])
    visited, pages = set(), []
    host = urlparse(start_url).hostname or ""
    while q and len(pages) < max_pages:
        url, depth = q.popleft()
        if url in visited or depth > depth_limit:
            continue
        visited.add(url)
        if on_event:
            on_event(url, "fetching")
        r = safe_get(url)
        if not r or not r.ok or "text/html" not in r.headers.get("content-type", ""):
            if on_event:
                on_event(url, "skipped")
            continue
        html = r.text[:300000]
        pages.append({"url": r.url, "html": html, "source_mode": "static"})
        if on_event:
            on_event(r.url, "visited")
        if depth >= depth_limit:
            continue
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
                continue
            full = urljoin(r.url, href)
            p = urlparse(full)
            if p.scheme not in ("http", "https") or (p.hostname or "") != host:
                continue
            links.append(f"{p.scheme}://{p.netloc}{p.path}")
        links = sorted(set(links), key=lambda u: sum(10 for x in PRIORITY if x in u.lower()), reverse=True)
        for link in links[:20]:
            if link not in visited:
                q.append((link, depth + 1))
    return pages


SMART_PATTERNS = ["sign up", "signup", "register", "continue", "next", "security", "add phone", "verify phone", "phone", "mobile", "otp", "verification", "two-factor", "2fa", "account"]


def smart_explore(start_url, click_limit=5, on_event=None):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        if on_event:
            on_event(start_url, "smart-explorer-unavailable")
        return []
    pages, seen = [], set()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(start_url, wait_until="domcontentloaded", timeout=25000)
            page.wait_for_timeout(1200)
            def snap(status):
                key = (page.url, status)
                if key in seen:
                    return
                seen.add(key)
                pages.append({"url": page.url, "html": page.content()[:300000], "source_mode": "smart"})
                if on_event:
                    on_event(page.url, status)
            snap("smart-loaded")
            host = urlparse(page.url).hostname or ""
            candidates = []
            for sel in ["button", "a", "[role='button']", "input[type='submit']"]:
                try:
                    loc = page.locator(sel)
                    count = min(loc.count(), 20)
                    for i in range(count):
                        try:
                            el = loc.nth(i)
                            if not el.is_visible():
                                continue
                            text = (el.inner_text(timeout=800) or "").strip()
                            score = sum(5 for pat in SMART_PATTERNS if pat in text.lower())
                            if score:
                                candidates.append((score, sel, i, text))
                        except Exception:
                            pass
                except Exception:
                    pass
            candidates.sort(reverse=True)
            clicked = 0
            for _, sel, idx, text in candidates:
                if clicked >= click_limit:
                    break
                try:
                    if on_event:
                        on_event(page.url, f"clicking: {text[:40] or sel}")
                    page.locator(sel).nth(idx).click(timeout=4000)
                    page.wait_for_timeout(1200)
                    if (urlparse(page.url).hostname or "") != host:
                        page.goto(start_url, wait_until="domcontentloaded", timeout=25000)
                        page.wait_for_timeout(800)
                        continue
                    snap(f"after-click:{text[:35]}")
                    clicked += 1
                    page.goto(start_url, wait_until="domcontentloaded", timeout=25000)
                    page.wait_for_timeout(800)
                except Exception:
                    pass
        finally:
            browser.close()
    return pages


def classify_page(url, html):
    soup = BeautifulSoup(html, "html.parser")
    text = ((soup.get_text(" ", strip=True) or "") + " " + url).lower()
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    phone = 0
    sms = 0
    evidence = []
    for inp in soup.find_all("input"):
        attrs = " ".join([str(inp.get("type", "")), str(inp.get("name", "")), str(inp.get("id", "")), str(inp.get("placeholder", ""))]).lower()
        if any(k in attrs for k in ["tel", "phone", "mobile"]):
            phone += 35
            evidence.append("Found phone-like input field")
        if any(k in attrs for k in ["otp", "code", "verification"]):
            sms += 15
            evidence.append("Found OTP/code-like input field")
    if re.search(r"send code|verify|continue|next|resend code|send otp|send sms|send", text, re.I):
        sms += 25
        evidence.append("Found send/verify style action")
    if re.search(r"phone number|mobile number|add phone|verify phone", text, re.I):
        phone += 20
        evidence.append("Matched phone clues in page text")
    if re.search(r"verification code|we sent you a code|otp|text message|verify by sms", text, re.I):
        sms += 20
        evidence.append("Matched SMS/OTP clues in page text")
    confidence = min(100, phone + sms)
    classification = "Weak Signal"
    summary = "No clear phone/SMS evidence found."
    if phone >= 25 and sms >= 30 and re.search(r"signup|register", text):
        classification, summary = "Signup Flow", "Likely requests phone verification during signup."
    elif phone >= 25 and sms >= 30:
        classification, summary = "SMS Verification", "Likely sends a code by SMS or asks for SMS verification."
    elif phone >= 25 and re.search(r"settings|security|account", text):
        classification, summary = "Post-Signup Phone Binding", "Likely adds or verifies phone after account creation."
    elif phone >= 20:
        classification, summary = "Phone Collection", "Likely collects a phone number."
    return {"title": title, "confidence": confidence, "classification": classification, "summary": summary, "evidence": list(dict.fromkeys(evidence))[:12], "testable": phone >= 25 and sms >= 25}


def analyze_web_target(label, url, settings, scan_id, db):
    pages = static_crawl(url, int(settings["max_pages"]), int(settings["crawl_depth"]), on_event=lambda u, s: log_event(db, scan_id, label, u, s))
    if settings["smart_explorer"]:
        more = smart_explore(url, int(settings["explorer_click_limit"]), on_event=lambda u, s: log_event(db, scan_id, label, u, s))
        seen = {(p["url"], p["source_mode"]) for p in pages}
        for p in more:
            k = (p["url"], p["source_mode"])
            if k not in seen:
                pages.append(p)
                seen.add(k)
    findings = []
    for p in pages:
        a = classify_page(p["url"], p["html"])
        if a["confidence"] < int(settings["min_save_confidence"]):
            continue
        findings.append({
            "target_label": label,
            "target_type": "web",
            "resolved_url": url,
            "page_url": p["url"],
            "classification": a["classification"],
            "confidence": a["confidence"],
            "testable": 1 if (a["testable"] and domain_allowed(p["url"], settings["allowed_domains"]) and a["confidence"] >= int(settings["confidence_threshold"])) else 0,
            "evidence_json": json.dumps(a["evidence"], ensure_ascii=False),
            "page_title": a["title"],
            "summary": a["summary"],
            "source_mode": p["source_mode"],
        })
    findings.sort(key=lambda x: (x["confidence"], x["testable"], 1 if x["source_mode"] == "smart" else 0), reverse=True)
    return findings[:30]


def analyze_app_target(url):
    low = url.lower()
    score = 0
    evidence = []
    for token in ["phone", "sms", "otp", "verify", "auth"]:
        if token in low:
            score += 15
            evidence.append(f"Matched token in app link: {token}")
    if score < 20:
        return []
    return [{
        "target_label": url,
        "target_type": "app",
        "resolved_url": url,
        "page_url": url,
        "classification": "SMS Verification" if score >= 30 else "Phone Collection",
        "confidence": min(100, score),
        "testable": 0,
        "evidence_json": json.dumps(evidence, ensure_ascii=False),
        "page_title": url,
        "summary": "App link suggests phone/SMS verification behavior.",
        "source_mode": "metadata",
    }]


def insert_findings(db, scan_id, findings):
    for f in findings:
        db.execute(
            "INSERT INTO findings (scan_id,target_label,target_type,resolved_url,page_url,classification,confidence,testable,evidence_json,page_title,created_at,summary,source_mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, f["target_label"], f["target_type"], f["resolved_url"], f["page_url"], f["classification"], f["confidence"], f["testable"], f["evidence_json"], f["page_title"], now_iso(), f["summary"], f["source_mode"]),
        )
    db.commit()


def run_scan_job(scan_id, raw_input):
    db = connect_db()
    try:
        settings = get_settings(db)
        lines = []
        seen = set()
        for line in raw_input.splitlines():
            item = clean_input(line)
            if item and item.lower() not in seen:
                seen.add(item.lower())
                lines.append(item)
        db.execute("UPDATE scans SET status='running', total_targets=? WHERE id=?", (len(lines), scan_id))
        db.commit()
        for idx, item in enumerate(lines, start=1):
            db.execute("UPDATE scans SET current_target=?, completed_targets=? WHERE id=?", (item, idx - 1, scan_id))
            db.commit()
            resolved = resolve_target(item)
            findings = []
            try:
                if resolved["kind"] == "web":
                    log_event(db, scan_id, item, resolved["url"], "target-start")
                    findings = analyze_web_target(item, resolved["url"], settings, scan_id, db)
                    log_event(db, scan_id, item, resolved["url"], "target-finished")
                elif resolved["kind"] == "app":
                    log_event(db, scan_id, item, resolved["url"], "metadata-check")
                    findings = analyze_app_target(resolved["url"])
            except Exception as e:
                log_event(db, scan_id, item, resolved["url"], f"error: {str(e)[:120]}")
            if findings:
                insert_findings(db, scan_id, findings)
            db.execute("UPDATE scans SET completed_targets=? WHERE id=?", (idx, scan_id))
            db.commit()
        count = db.execute("SELECT COUNT(*) c FROM findings WHERE scan_id=?", (scan_id,)).fetchone()["c"]
        db.execute("UPDATE scans SET status='done', current_target='', notes=? WHERE id=?", ("تم الفحص." if count else "انتهى الفحص بدون نتائج مطابقة للشروط.", scan_id))
        db.commit()
    except Exception as e:
        db.execute("UPDATE scans SET status='failed', notes=? WHERE id=?", (str(e)[:250], scan_id))
        db.commit()
    finally:
        db.close()


def run_basic_owned_site_test(finding, phone_number):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return ("failed", "Playwright is not installed or unavailable in this deployment.")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(finding["page_url"], wait_until="domcontentloaded", timeout=25000)
        for sel in ['input[type="tel"]','input[name*="phone" i]','input[id*="phone" i]','input[placeholder*="phone" i]']:
            loc = page.locator(sel)
            if loc.count() > 0 and loc.first.is_visible():
                loc.first.fill(phone_number or "")
                browser.close()
                return ("success", "Filled phone number successfully.")
        browser.close()
        return ("failed", "No visible phone input found.")


@app.context_processor
def inject_globals():
    return {"APP_TITLE": APP_TITLE}


@app.route("/")
def dashboard():
    db = get_db()
    stats = {
        "targets": db.execute("SELECT COUNT(DISTINCT target_label) c FROM findings").fetchone()["c"] or 0,
        "web_results": db.execute("SELECT COUNT(*) c FROM findings WHERE target_type='web'").fetchone()["c"] or 0,
        "app_results": db.execute("SELECT COUNT(*) c FROM findings WHERE target_type='app'").fetchone()["c"] or 0,
        "testable": db.execute("SELECT COUNT(*) c FROM findings WHERE testable=1").fetchone()["c"] or 0,
        "tests": 0,
    }
    recent = db.execute("SELECT * FROM findings ORDER BY id DESC LIMIT 8").fetchall()
    scans = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent, scans=scans)


@app.route("/scan", methods=["GET", "POST"])
def scan():
    settings = get_settings()
    if request.method == "POST":
        raw = request.form.get("targets", "").strip()
        if not raw:
            flash("أدخل هدفًا واحدًا على الأقل.", "error")
            return redirect(url_for("scan"))
        db = get_db()
        cur = db.execute("INSERT INTO scans (created_at, raw_input, status, notes) VALUES (?, ?, 'queued', '')", (now_iso(), raw))
        scan_id = cur.lastrowid
        db.commit()
        t = threading.Thread(target=run_scan_job, args=(scan_id, raw), daemon=True)
        SCAN_THREADS[scan_id] = t
        t.start()
        return redirect(url_for("scan_progress", scan_id=scan_id))
    return render_template("scan.html", settings=settings)


@app.route("/scan/<int:scan_id>/progress")
def scan_progress(scan_id):
    scan = get_db().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        flash("عملية الفحص غير موجودة.", "error")
        return redirect(url_for("dashboard"))
    return render_template("progress.html", scan=scan)


@app.route("/scan_status/<int:scan_id>")
def scan_status(scan_id):
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        return jsonify({"ok": False}), 404
    total = scan["total_targets"] or 0
    completed = scan["completed_targets"] or 0
    percent = 5 if scan["status"] == "queued" else 100 if scan["status"] == "done" else min(95, int((completed / total) * 100)) if total else 10
    events = db.execute("SELECT target_label,url,status,created_at FROM crawl_events WHERE scan_id=? ORDER BY id DESC LIMIT 80", (scan_id,)).fetchall()
    findings_count = db.execute("SELECT COUNT(*) c FROM findings WHERE scan_id=?", (scan_id,)).fetchone()["c"]
    return jsonify({"ok": True, "status": scan["status"], "notes": scan["notes"] or "", "current_target": scan["current_target"] or "", "completed_targets": completed, "total_targets": total, "percent": percent, "findings_count": findings_count, "events": [dict(e) for e in events], "results_url": url_for("results", scan_id=scan_id)})


@app.route("/results")
def results():
    db = get_db()
    scan_id = request.args.get("scan_id", type=int)
    if scan_id:
        findings = db.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY confidence DESC, id DESC", (scan_id,)).fetchall()
        scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    else:
        findings = db.execute("SELECT * FROM findings ORDER BY id DESC LIMIT 100").fetchall()
        scan = None
    return render_template("results.html", findings=findings, scan=scan)


@app.route("/finding/<int:finding_id>")
def finding_detail(finding_id):
    db = get_db()
    finding = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not finding:
        flash("النتيجة غير موجودة.", "error")
        return redirect(url_for("results"))
    evidence = json.loads(finding["evidence_json"] or "[]")
    return render_template("detail.html", finding=finding, evidence=evidence, settings=get_settings())


@app.route("/delete_finding/<int:finding_id>", methods=["POST"])
def delete_finding(finding_id):
    db = get_db()
    db.execute("DELETE FROM findings WHERE id=?", (finding_id,))
    db.commit()
    flash("تم حذف النتيجة.", "success")
    return redirect(request.referrer or url_for("results"))


@app.route("/delete_scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    db = get_db()
    db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    db.execute("DELETE FROM crawl_events WHERE scan_id=?", (scan_id,))
    db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    db.commit()
    flash("تم حذف نتائج عملية الفحص.", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete_all", methods=["POST"])
def delete_all():
    db = get_db()
    db.execute("DELETE FROM findings")
    db.execute("DELETE FROM crawl_events")
    db.execute("DELETE FROM scans")
    db.commit()
    flash("تم حذف كل النتائج والسجلات.", "success")
    return redirect(url_for("dashboard"))


@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    if request.method == "POST":
        save_settings(request.form)
        flash("تم حفظ الإعدادات.", "success")
        return redirect(url_for("settings_page"))
    return render_template("settings.html", settings=get_settings())


@app.route("/test/<int:finding_id>", methods=["POST"])
def run_test(finding_id):
    db = get_db()
    finding = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    settings = get_settings()
    if not finding:
        flash("النتيجة غير موجودة.", "error")
        return redirect(url_for("results"))
    if finding["target_type"] != "web" or not finding["testable"]:
        flash("هذه النتيجة غير مؤهلة للاختبار.", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id))
    if not domain_allowed(finding["page_url"], settings.get("allowed_domains", "")):
        flash("الدومين غير موجود في قائمة الدومينات المسموح اختبارها.", "error")
        return redirect(url_for("finding_detail", finding_id=finding_id))
    status, message = run_basic_owned_site_test(finding, settings.get("default_phone", ""))
    flash(message, "success" if status == "success" else "error")
    return redirect(url_for("finding_detail", finding_id=finding_id))


@app.route("/health")
def health():
    return {"ok": True, "app": APP_TITLE}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT, debug=False)

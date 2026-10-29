"""Email the bank's security admin through Mailgun: a PDF of the latest scan, or a CRITICAL alert when a change broke the bank.

Banks and their admins come from .env (see .env.example):
  PQB_BANKS=pqbank,otherbank
  BANK_<ID>_NAME, BANK_<ID>_ADMIN_NAME, BANK_<ID>_ADMIN_EMAILS (comma separated)
Mailgun: MAILGUN_API_KEY, MAILGUN_DOMAIN, MAILGUN_FROM, MAILGUN_API_BASE.
The scan data is the console's latest scan (evidence/inventory.json); it currently covers PQBank only.
"""
import io
import json
import os
import re
import time
from collections import Counter
from xml.sax.saxutils import escape

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import config, migrate, pipeline, testbed
from .tasks import TASK_BY_ID

LOG_FILE = config.EVIDENCE / "notifications.jsonl"
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
COOLDOWN_S = 30
_last_sent = {}
_EMAIL = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")

INK, BRAND, MUTED, RULE = colors.HexColor("#111111"), colors.HexColor("#163A96"), colors.HexColor("#5b5b5b"), colors.HexColor("#c9c1b5")
SEV_COLOR = {"critical": colors.HexColor("#b3261e"), "high": colors.HexColor("#d9480f"), "medium": colors.HexColor("#b7791f"), "low": MUTED}


def _env(name, default=""):
    return os.environ.get(name, default).strip()


def _prefix(bank_id):
    return "BANK_" + re.sub(r"\W", "_", bank_id.upper()) + "_"


def banks():
    """Banks configured in .env, in order. Each: id, name, admin_name, emails (valid ones), invalid (rejected ones)."""
    out = []
    for bid in [b.strip().lower() for b in _env("PQB_BANKS", "pqbank").split(",") if b.strip()]:
        p = _prefix(bid)
        raw = [e.strip() for e in re.split(r"[,;]", _env(p + "ADMIN_EMAILS")) if e.strip()]
        out.append({"id": bid, "name": _env(p + "NAME") or bid, "admin_name": _env(p + "ADMIN_NAME"),
                    "emails": [e for e in raw if _EMAIL.match(e)], "invalid": [e for e in raw if not _EMAIL.match(e)]})
    return out


def mailgun():
    key, domain = _env("MAILGUN_API_KEY"), _env("MAILGUN_DOMAIN")
    return {"key": key, "domain": domain, "from": _env("MAILGUN_FROM") or f"PQ-Bridge Security <security@{domain}>",
            "base": (_env("MAILGUN_API_BASE") or "https://api.mailgun.net").rstrip("/"), "ready": bool(key and domain)}


def _mask(email):
    user, _, host = email.partition("@")
    return f"{user[:1]}***@{host}"


def public_config():
    mg = mailgun()
    return {"mailgun_ready": mg["ready"],
            "banks": [{"id": b["id"], "name": b["name"], "admin_name": b["admin_name"], "recipients": [_mask(e) for e in b["emails"]],
                       "invalid": len(b["invalid"])} for b in banks()]}


def _ev(name, default):
    try:
        return json.loads((config.EVIDENCE / name).read_text())
    except Exception:
        return default


def summary():
    """Numbers shared by the PDF and the email body."""
    findings = _ev("inventory.json", [])
    vuln = [f for f in findings if f.get("status") == "quantum-vulnerable"]
    sev = Counter(f.get("severity") or "low" for f in vuln)
    return {"findings": findings, "vuln": vuln, "sev": sev, "services": sorted({f.get("service") or "-" for f in vuln}),
            "categories": Counter(f.get("category") for f in vuln), "scanned": (config.EVIDENCE / "inventory.json").stat().st_mtime
            if (config.EVIDENCE / "inventory.json").exists() else None}


def build_pdf(bank, s):
    risk, plan = _ev("risk.json", {}), _ev("plan.json", {})
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK, alignment=TA_LEFT)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10.5)
    cell = ParagraphStyle("c", parent=body, fontSize=8, leading=10)
    h1 = ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=INK)
    h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=BRAND, spaceBefore=14, spaceAfter=6)
    P = lambda t, st=body: Paragraph(escape(str(t)), st)

    def table(rows, widths):
        t = Table(rows, colWidths=widths, repeatRows=1)
        style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                 ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 4)]
        style += [("BACKGROUND", (0, 0), (-1, 0), BRAND), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, 0), 8)]
        t.setStyle(TableStyle(style))
        return t

    when = time.strftime("%d %B %Y, %H:%M", time.localtime())
    scanned = time.strftime("%d %B %Y, %H:%M", time.localtime(s["scanned"])) if s["scanned"] else "unknown"
    n_vuln, crit_high = len(s["vuln"]), s["sev"]["critical"] + s["sev"]["high"]
    at_risk = [n for n, v in (risk.get("services") or {}).items() if (v.get("mosca") or {}).get("at_risk")]
    story = [P("PQ-BRIDGE  ·  QUANTUM-VULNERABILITY REPORT", ParagraphStyle("k", parent=small, textColor=BRAND, fontName="Helvetica-Bold")),
             Spacer(1, 4), P(bank["name"], h1), P(f"Prepared for {bank['admin_name'] or 'the bank security administrator'}  ·  Report generated {when}  ·  Scan completed {scanned}", small),
             Spacer(1, 10)]

    tiles = [[P(str(len(s["findings"])), h1), P(str(n_vuln), ParagraphStyle("r", parent=h1, textColor=SEV_COLOR["critical"])),
              P(str(crit_high), ParagraphStyle("o", parent=h1, textColor=SEV_COLOR["high"])), P(str(len(s["services"])), h1)],
             [P("items checked", small), P("quantum-vulnerable", small), P("critical or high severity", small), P("services affected", small)]]
    t = Table(tiles, colWidths=[42 * mm] * 4)
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 1, INK), ("LINEAFTER", (0, 0), (-2, -1), 0.4, RULE), ("TOPPADDING", (0, 0), (-1, -1), 4),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f1ea"))]))
    story += [t, Spacer(1, 8)]

    story += [P("What this means", h2),
              P(f"The scan found {n_vuln} places where {bank['name']} still relies on cryptography that a future quantum computer can break "
                f"(RSA, ECDSA, ECDH, X25519). Attackers can record encrypted traffic today and decrypt it once such a computer exists, so data that must stay "
                f"confidential for years is already exposed. By the standard shelf-life test (how long the data must stay secret, plus how long migration takes, "
                f"compared with the years until a quantum computer), {len(at_risk)} service(s) are at risk now"
                + (": " + ", ".join(at_risk) + "." if at_risk else "."))]

    story += [P("Findings by severity and by type", h2)]
    sev_rows = [["Severity", "Findings"]] + [[s_.title(), s["sev"][s_]] for s_ in SEVERITY_ORDER if s["sev"][s_]]
    cat_name = {"certificate": "Certificates", "config": "Configuration files", "endpoint": "Live TLS endpoints", "code": "Source code", "dependency": "Dependencies"}
    cat_rows = [["Where found", "Findings"]] + [[cat_name.get(c, c), n] for c, n in s["categories"].most_common()]
    side = Table([[table(sev_rows, [35 * mm, 25 * mm]), table(cat_rows, [45 * mm, 25 * mm])]], colWidths=[85 * mm, 90 * mm])
    side.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [side]

    if risk.get("services"):
        story += [P("Services ranked by risk", h2), P("Score is 0 to 10 (higher is more urgent). It combines exposure, how critical the service is and how long its data must stay secret.", small), Spacer(1, 4)]
        rows = [["Service", "Risk score", "Vulnerable findings", "Data must stay secret (years)", "At risk now"]]
        for name, v in sorted(risk["services"].items(), key=lambda kv: -kv[1].get("score", 0)):
            rows.append([name, v.get("score"), v.get("findings"), v.get("shelf_life_years"), "YES" if (v.get("mosca") or {}).get("at_risk") else "no"])
        story.append(table(rows, [32 * mm, 25 * mm, 38 * mm, 50 * mm, 25 * mm]))

    story += [P(f"All quantum-vulnerable findings ({n_vuln})", h2),
              P("Sorted by severity. 'Where' is the file and line, certificate or live endpoint where the weak algorithm was seen.", small), Spacer(1, 4)]
    order = {k: i for i, k in enumerate(SEVERITY_ORDER)}
    rows = [["Severity", "Service", "Where", "Algorithm", "Found by"]]
    for f in sorted(s["vuln"], key=lambda f: (order.get(f.get("severity"), 9), f.get("service") or "", f.get("file") or "")):
        sev = f.get("severity") or "low"
        where = (f.get("file") or "") + (f":{f['line']}" if f.get("line") else "")
        rows.append([P(sev.upper(), ParagraphStyle("sv", parent=cell, fontName="Helvetica-Bold", textColor=SEV_COLOR.get(sev, MUTED))), P(f.get("service") or "-", cell),
                     P(where, cell), P(f.get("algorithm") or "", cell), P(cat_name.get(f.get("category"), f.get("category") or ""), cell)])
    story.append(table(rows, [17 * mm, 22 * mm, 64 * mm, 40 * mm, 31 * mm]))

    waves = plan.get("final_waves")
    if waves:
        titles = {t["id"]: t["title"] for t in plan.get("tasks", [])}
        story += [P("Recommended fix plan", h2),
                  P("PQ-Bridge orders the migration by risk, dependencies, engineer capacity and the month-end freeze. Each window ends with a verification gate that rolls the change back if customers are affected.", small), Spacer(1, 4)]
        for w, ids in enumerate(waves):
            story.append(P(f"Window {w}  ·  {len(ids)} tasks", ParagraphStyle("w", parent=body, fontName="Helvetica-Bold", spaceBefore=6)))
            for tid in ids:
                story.append(P(f"-  {titles.get(tid, tid)}", ParagraphStyle("li", parent=small, leftIndent=10)))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"PQ-Bridge  ·  {bank['name']}  ·  Confidential, for the bank security administrator")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                      title=f"PQ-Bridge report: {bank['name']}", author="PQ-Bridge").build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def _log(rec):
    rec["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def _ready(bank_id):
    """The bank and Mailgun settings to send with, or RuntimeError saying what to set in .env."""
    all_banks = banks()
    bank = next((b for b in all_banks if b["id"] == (bank_id or all_banks[0]["id"]).lower()), None) if all_banks else None
    if not bank:
        raise RuntimeError(f"unknown bank '{bank_id}'. Configured: {', '.join(b['id'] for b in all_banks) or 'none'} (PQB_BANKS in .env)")
    mg = mailgun()
    if not mg["ready"]:
        raise RuntimeError("Mailgun is not configured. Set MAILGUN_API_KEY and MAILGUN_DOMAIN in .env and restart.")
    if not bank["emails"]:
        bad = f" ({len(bank['invalid'])} invalid address(es) ignored)" if bank["invalid"] else ""
        raise RuntimeError(f"no admin email for {bank['name']}{bad}. Set {_prefix(bank['id'])}ADMIN_EMAILS in .env and restart.")
    return bank, mg


def _cooldown(key):
    wait = COOLDOWN_S - (time.time() - _last_sent.get(key, 0))
    if wait > 0:
        raise RuntimeError(f"that email was just sent. Wait {wait:.0f} s before sending another.")


def _deliver(bank, mg, kind, subject, text, html=None, attachment=None):
    """One Mailgun message to every admin of the bank. Returns the Mailgun message id."""
    data = {"from": mg["from"], "to": bank["emails"], "subject": subject, "text": text}
    if html:
        data["html"] = html
    try:
        r = requests.post(f"{mg['base']}/v3/{mg['domain']}/messages", auth=("api", mg["key"]), timeout=30, data=data,
                          files=[("attachment", attachment)] if attachment else None)
    except requests.RequestException as e:
        _log({"bank": bank["id"], "kind": kind, "ok": False, "error": type(e).__name__})
        raise RuntimeError(f"could not reach Mailgun ({type(e).__name__}). Check the network and MAILGUN_API_BASE.")
    if r.status_code != 200:
        detail = (r.json().get("message") if r.headers.get("content-type", "").startswith("application/json") else r.text[:200]) or r.reason
        _log({"bank": bank["id"], "kind": kind, "ok": False, "status": r.status_code, "error": detail})
        hint = " Check MAILGUN_API_KEY (EU accounts also need MAILGUN_API_BASE=https://api.eu.mailgun.net)." if r.status_code in (401, 403) else ""
        raise RuntimeError(f"Mailgun refused the message ({r.status_code}): {detail}.{hint}")
    _last_sent[kind + ":" + bank["id"]] = time.time()
    return r.json().get("id")


def send_report(bank_id=None):
    """Build the PDF from the latest scan and email it to the bank's admin(s). Raises RuntimeError with a plain reason on refusal."""
    bank, mg = _ready(bank_id)
    s = summary()
    if not s["findings"]:
        raise RuntimeError("no scan results yet. Scan the bank first.")
    _cooldown("report:" + bank["id"])

    pdf = build_pdf(bank, s)
    crit, high, n = s["sev"]["critical"], s["sev"]["high"], len(s["vuln"])
    subject = f"[PQ-Bridge] {bank['name']}: {n} quantum-vulnerable findings ({crit} critical, {high} high)"
    greeting = f"Hello {bank['admin_name']}," if bank["admin_name"] else "Hello,"
    text = (f"{greeting}\n\nPQ-Bridge scanned {bank['name']} and found {n} places that use cryptography a quantum computer can break "
            f"({crit} critical, {high} high) across {len(s['services'])} services: {', '.join(s['services'])}.\n\n"
            f"The attached PDF lists every finding, ranks the services by risk and gives the recommended fix order.\n\n- PQ-Bridge security console")
    fname = f"pqbridge-{bank['id']}-{time.strftime('%Y%m%d-%H%M')}.pdf"
    mid = _deliver(bank, mg, "report", subject, text, attachment=(fname, pdf, "application/pdf"))
    _log({"bank": bank["id"], "kind": "report", "ok": True, "recipients": len(bank["emails"]), "findings": n, "mailgun_id": mid})
    pipeline.log(f"EMAILED report for {bank['name']} to {len(bank['emails'])} recipient(s), {n} findings, {len(pdf) // 1024} KB PDF")
    return {"ok": True, "sent": True, "bank": bank["name"], "recipients": [_mask(e) for e in bank["emails"]], "findings": n, "pdf_kb": len(pdf) // 1024}


# ---------------------------------------------------------------- critical alert: a change broke the bank
def incident():
    """Is the customer path broken right now? Runs the live canary (sign in, read, pay, retry). If it is, say which change left it that way."""
    cv = migrate.canary(tries=2, pause=2.0)
    out = {"broken": not cv.get("ok"), "failing": [{"name": x["name"], "detail": x.get("detail", "")} for x in cv.get("steps", []) if not x.get("ok")],
           "change": None}
    last = next((e for e in migrate.events(40) if e.get("type") in ("apply", "rollback")), None)
    if out["broken"] and last and last.get("type") == "apply" and last.get("passed") is False and not last.get("rollback"):
        st = testbed.read_state()
        tasks = last.get("tasks") or []
        unmet = {t: [d for d in TASK_BY_ID[t]["deps"] if not migrate.task_done(d, st)] for t in tasks if t in TASK_BY_ID}
        out["change"] = {
            "tasks": tasks, "when": last.get("started") or last.get("ts"), "auto_rollback": bool(last.get("auto_rollback")),
            "unmet": {t: d for t, d in unmet.items() if d},
            "checks": [{"name": c["name"], "detail": c.get("detail", "")} for c in last.get("checks", []) if not c.get("passed")][:6]}
    return out


def _clip(t, n=170):
    t = " ".join(str(t).split())
    return t if len(t) <= n else t[:n - 1] + "..."


def _lines(rows, detail=True):
    return [f"{x['name']}: {_clip(x['detail'], 110)}" if detail and x["detail"] else x["name"] for x in rows]


def alert_email(bank, inc):
    """Subject, plain text and HTML for the CRITICAL alert."""
    ch = inc["change"]
    greeting = f"Hello {bank['admin_name']}," if bank["admin_name"] else "Hello,"
    if ch:
        when = time.strftime("%d %b %Y, %H:%M", time.localtime(ch["when"])) if ch["when"] else "earlier"
        what = (f"At {when} an operator applied {', '.join(ch['tasks'])} with FORCE" + (", skipping its prerequisites" if ch["unmet"] else "")
                + ", and with automatic rollback OFF. The safety checks failed and the change was left in place, "
                "so the bank is running on a broken configuration.")
        subject = f"[CRITICAL] {bank['name']} is not working: forced change left in place"
        steps = ["Open the PQ-Bridge console and go to Migrate.",
                 "Click \"Rollback last change\". It restores the previous configuration in about a second.",
                 "Click \"Run verification gate\" and confirm every check passes.",
                 "Before trying the change again, apply its missing prerequisites first (use \"Apply + prerequisites\")."]
    else:
        what = ("The customer path is failing, and PQ-Bridge has no failed change left in place that explains it. "
                "Check recent changes and the health of the bank's services.")
        subject = f"[CRITICAL] {bank['name']} is not working: customer path failing"
        steps = ["Open the PQ-Bridge console and run the verification gate (Dashboard or Migrate).",
                 "Check which service is failing and whether a recent change touched it; roll it back if so.",
                 "Confirm customers can sign in and pay again before closing this alert."]
    headline = f"{bank['name']} is NOT WORKING for customers right now."
    impact = ("Customers cannot complete payments right now: they see the red \"payment failed\" screen. "
              "A payment shown as failed is never posted later, so nothing is paid twice.")
    unmet = [f"{t} needs {', '.join(d)}, which {'is' if len(d) == 1 else 'are'} not applied" for t, d in (ch["unmet"] if ch else {}).items()]
    seen = {x["name"] for x in inc["failing"]}
    fails, gate = _lines(inc["failing"]), _lines([x for x in (ch["checks"] if ch else []) if x["name"] not in seen][:3], detail=False)

    def block(title, rows):
        return (f"\n{title}\n" + "\n".join(f"  - {r}" for r in rows) + "\n") if rows else ""
    text = (f"{greeting}\n\nCRITICAL: {headline}\n\nWHAT HAPPENED\n{what}\n" + block("MISSING PREREQUISITES", unmet)
            + block("WHAT IS FAILING NOW", fails) + block("SAFETY CHECKS THAT FAILED", gate)
            + f"\nCUSTOMER IMPACT\n{impact}\n\nWHAT TO DO NOW (about 1 minute)\n"
            + "\n".join(f"  {i}. {x}" for i, x in enumerate(steps, 1)) + "\n\n- PQ-Bridge security console\n")

    def li(rows):
        return "".join(f"<li style='margin:0 0 6px'>{escape(r)}</li>" for r in rows)

    def sect(title, inner):
        h = f"<h3 style='margin:22px 0 6px;font:700 13px Arial,sans-serif;letter-spacing:.08em;color:#163A96;text-transform:uppercase'>{title}</h3>"
        return h + inner if inner else ""
    ul = lambda rows, extra="": f"<ul style='margin:0;padding-left:20px;{extra}'>{li(rows)}</ul>" if rows else ""
    html = ("<div style='max-width:620px;margin:0 auto;font:15px/1.5 Arial,sans-serif;color:#111'>"
            "<div style='background:#b3261e;color:#fff;padding:16px 20px;border-radius:4px 4px 0 0'>"
            "<div style='font:700 12px Arial;letter-spacing:.14em'>CRITICAL ALERT &middot; PQ-BRIDGE</div>"
            f"<div style='font:700 22px/1.25 Arial;margin-top:4px'>{escape(headline)}</div></div>"
            f"<div style='border:1px solid #c9c1b5;border-top:0;padding:8px 20px 20px'><p>{escape(greeting)}</p>"
            + sect("What happened", f"<p style='margin:0'>{escape(what)}</p>")
            + sect("Missing prerequisites", ul(unmet)) + sect("What is failing now", ul(fails))
            + sect("Safety checks that failed", ul(gate, "color:#444;font-size:13px;"))
            + sect("Customer impact", f"<p style='margin:0'>{escape(impact)}</p>")
            + "<div style='margin-top:22px;background:#f5f1ea;border-left:5px solid #F5B700;padding:12px 16px'><b>What to do now (about 1 minute)</b>"
              f"<ol style='margin:8px 0 0;padding-left:20px'>{li(steps)}</ol></div>"
            + "<p style='margin:20px 0 0;color:#5b5b5b;font-size:12px'>PQ-Bridge security console</p></div></div>")
    return subject, text, html


def send_alert(bank_id=None):
    """Email a CRITICAL alert, but only if the customer path is broken right now. A healthy bank sends nothing."""
    bank, mg = _ready(bank_id)
    _cooldown("alert:" + bank["id"])
    inc = incident()
    if not inc["broken"]:
        pipeline.log(f"ALERT not sent for {bank['name']}: customer path is healthy")
        return {"ok": True, "sent": False, "bank": bank["name"],
                "reason": f"{bank['name']} is working: sign in, reads and payments all pass right now, so no alert was sent."}
    subject, text, html = alert_email(bank, inc)
    mid = _deliver(bank, mg, "alert", subject, text, html)
    tasks = (inc["change"] or {}).get("tasks") or []
    _log({"bank": bank["id"], "kind": "alert", "ok": True, "recipients": len(bank["emails"]), "change": tasks, "mailgun_id": mid})
    pipeline.log(f"EMAILED CRITICAL alert for {bank['name']} to {len(bank['emails'])} recipient(s): {subject}")
    return {"ok": True, "sent": True, "bank": bank["name"], "recipients": [_mask(e) for e in bank["emails"]], "change": tasks, "failing": len(inc["failing"])}

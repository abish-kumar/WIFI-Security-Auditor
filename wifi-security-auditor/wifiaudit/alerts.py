"""
Alert delivery for Live Monitor / `watch`. Two channels, both optional and off by default:

  - email via SMTP (credentials stored in config.json's "alerts.email" section)
  - a webhook URL in Slack's or Discord's incoming-webhook JSON shape (auto-detected by URL)

Nothing here is called automatically; the caller (web.py / auditor.py watch loop) decides
when to send. Sending requires network access this sandbox does not have, so this module
is covered by tests that check message formatting and config validation, not live delivery.
"""
from __future__ import annotations

import json
import re
import smtplib
import urllib.error
import urllib.request
from email.mime.text import MIMEText


class AlertError(Exception):
    pass


def send_email(cfg, subject, body):
    e = (cfg or {}).get("alerts", {}).get("email") or {}
    required = ("host", "port", "user", "password", "to")
    missing = [k for k in required if not e.get(k)]
    if missing:
        raise AlertError(f"Email alert is not configured (missing: {', '.join(missing)})")
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = e.get("from") or e["user"]
    msg["To"] = e["to"]
    cls = smtplib.SMTP_SSL if int(e.get("port", 587)) == 465 else smtplib.SMTP
    try:
        with cls(e["host"], int(e["port"]), timeout=10) as conn:
            if cls is smtplib.SMTP:
                conn.starttls()
            conn.login(e["user"], e["password"])
            conn.sendmail(msg["From"], [e["to"]], msg.as_string())
    except (OSError, smtplib.SMTPException) as exc:
        raise AlertError(f"Could not send email: {exc}") from exc
    return True


def _webhook_payload(url, text):
    if "discord.com" in url:
        return {"content": text[:1900]}
    return {"text": text[:3000]}            # Slack / Mattermost / Teams-compatible-enough


def send_webhook(cfg, text):
    url = ((cfg or {}).get("alerts", {}).get("webhook_url") or "").strip()
    if not url:
        raise AlertError("No webhook URL configured")
    if not re.match(r"^https://", url):
        raise AlertError("Webhook URL must start with https://")
    data = json.dumps(_webhook_payload(url, text)).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status < 300
    except (urllib.error.URLError, OSError) as e:
        raise AlertError(f"Webhook delivery failed: {e}") from e


def dispatch(cfg, title, lines):
    """Send to every configured channel; returns {"email": bool|str, "webhook": bool|str}."""
    body = title + "\n\n" + "\n".join("- " + l for l in lines)
    result = {}
    a = (cfg or {}).get("alerts", {})
    if a.get("email", {}).get("host"):
        try:
            send_email(cfg, title, body)
            result["email"] = True
        except AlertError as e:
            result["email"] = str(e)
    if a.get("webhook_url"):
        try:
            send_webhook(cfg, body)
            result["webhook"] = True
        except AlertError as e:
            result["webhook"] = str(e)
    return result


def set_alert_config(path, email=None, webhook_url=None):
    from .config import load_config, save_config
    cfg = load_config(path)
    a = cfg.setdefault("alerts", {})
    if email is not None:
        a["email"] = email
    if webhook_url is not None:
        a["webhook_url"] = webhook_url
    save_config(path, cfg)
    return a

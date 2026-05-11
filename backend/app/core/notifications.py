"""Email notification service with pluggable backends.

Backend selected via env `EMAIL_BACKEND`:
  - "console" (default) — logs the email to stdout. Safe for dev + first deploy.
  - "smtp"              — sends via SMTP using SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD/SMTP_TLS.

Callers should use `send_email(to, subject, body_text, body_html=None)`.

Failures are logged but never raised — a missing invite email shouldn't crash
the API call that triggered it.
"""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _backend() -> str:
    return _env("EMAIL_BACKEND", "console").lower().strip()


def _from_address() -> str:
    return _env("EMAIL_FROM", "no-reply@adauditai.local")


def send_email(
    to: str, subject: str, body_text: str, body_html: str | None = None,
) -> bool:
    """Send an email. Returns True on apparent success, False on failure.

    Never raises — auditing the failure is the only consequence.
    """
    if not to or "@" not in to:
        logger.warning("email_invalid_recipient", extra={"to": to})
        return False

    backend = _backend()
    try:
        if backend == "console":
            return _send_console(to, subject, body_text, body_html)
        if backend == "smtp":
            return _send_smtp(to, subject, body_text, body_html)
        logger.warning("email_unknown_backend", extra={"backend": backend})
        return False
    except Exception as exc:
        logger.exception("email_send_failed", extra={"error": str(exc), "to": to})
        return False


def _send_console(to: str, subject: str, body: str, body_html: str | None) -> bool:
    """Log the email to stdout — useful for dev + as a fallback."""
    logger.info(
        "email_console",
        extra={"to": to, "subject": subject, "from": _from_address()},
    )
    # Print so the dev sees the message body inline
    print("\n" + "=" * 70, flush=True)
    print(f"[EMAIL] To: {to}", flush=True)
    print(f"[EMAIL] From: {_from_address()}", flush=True)
    print(f"[EMAIL] Subject: {subject}", flush=True)
    print("-" * 70, flush=True)
    print(body, flush=True)
    print("=" * 70 + "\n", flush=True)
    return True


def _send_smtp(to: str, subject: str, body_text: str, body_html: str | None) -> bool:
    host = _env("SMTP_HOST")
    port = int(_env("SMTP_PORT", "587"))
    user = _env("SMTP_USER")
    pwd = _env("SMTP_PASSWORD")
    use_tls = _env("SMTP_TLS", "true").lower() in ("true", "1", "yes")

    if not host:
        logger.warning("smtp_no_host_configured")
        return False

    msg = MIMEMultipart("alternative") if body_html else MIMEMultipart()
    msg["From"] = _from_address()
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        msg.attach(MIMEText(body_html, "html", "utf-8"))

    with smtplib.SMTP(host, port, timeout=15) as srv:
        if use_tls:
            srv.starttls()
        if user and pwd:
            srv.login(user, pwd)
        srv.sendmail(_from_address(), [to], msg.as_string())
    logger.info("email_sent_smtp", extra={"to": to, "subject": subject})
    return True

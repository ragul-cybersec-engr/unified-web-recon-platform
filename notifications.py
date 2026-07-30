import os
import smtplib
from email.message import EmailMessage
from typing import Iterable, Optional, Tuple

import yaml


def _to_bool(value, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_smtp_config(config_path: str = "config.yaml") -> Optional[dict]:
    file_cfg = {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            parsed = yaml.safe_load(f) or {}
            file_cfg = parsed.get("Notifications", {}).get("smtp", {}) or {}
    except FileNotFoundError:
        file_cfg = {}

    host = os.getenv("SMTP_HOST") or file_cfg.get("host")
    if not host:
        return None

    port = int(os.getenv("SMTP_PORT") or file_cfg.get("port") or 587)
    username = os.getenv("SMTP_USERNAME") or file_cfg.get("username") or ""
    password = os.getenv("SMTP_PASSWORD") or file_cfg.get("password") or ""
    sender = os.getenv("SMTP_SENDER") or file_cfg.get("sender") or username
    use_tls = _to_bool(os.getenv("SMTP_USE_TLS"), _to_bool(file_cfg.get("use_tls"), True))
    use_ssl = _to_bool(os.getenv("SMTP_USE_SSL"), _to_bool(file_cfg.get("use_ssl"), False))

    if not sender:
        raise ValueError("SMTP sender email is required in config or environment")

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "sender": sender,
        "use_tls": use_tls,
        "use_ssl": use_ssl,
    }


def send_email(
    recipient: str,
    subject: str,
    body: str,
    attachments: Optional[Iterable[Tuple[str, bytes, str]]] = None,
    config_path: str = "config.yaml",
):
    cfg = load_smtp_config(config_path=config_path)
    if not cfg:
        raise ValueError(
            "SMTP is not configured. Set Notifications.smtp in config.yaml or SMTP_* environment variables."
        )

    msg = EmailMessage()
    msg["From"] = cfg["sender"]
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    for filename, content, mime in attachments or []:
        if "/" in mime:
            maintype, subtype = mime.split("/", 1)
        else:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)

    if cfg["use_ssl"]:
        server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=30)
    else:
        server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=30)

    with server:
        if cfg["use_tls"] and not cfg["use_ssl"]:
            server.starttls()
        if cfg["username"] and cfg["password"]:
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg)

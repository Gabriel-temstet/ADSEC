"""Sanitisation des rapports generes (`adsec report --sanitize`).

Masque automatiquement : noms sensibles si configure, IP, emails, secrets
(reprend `redact` de l'audit log pour password/token/ticket/hash/secret).
Preserve suffisamment de contexte pour comprendre le finding (ex: une IP
devient `[IP MASQUEE]`, pas un simple retrait du texte)."""

from __future__ import annotations

import re

from adsec.core.events.audit_log import redact

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def sanitize_text(text: str) -> str:
    text = redact(text)
    text = _IPV4_RE.sub("[IP MASQUEE]", text)
    text = _EMAIL_RE.sub("[EMAIL MASQUE]", text)
    return text

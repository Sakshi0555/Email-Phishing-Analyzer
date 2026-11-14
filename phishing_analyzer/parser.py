"""M1 - Parse raw .eml files into a normalized ParsedEmail object.

Uses only the standard library email module. Every downstream module
(headers.py, links.py, domains.py, scoring.py) consumes a ParsedEmail
instance rather than touching the raw email.message.Message directly,
so parsing quirks are handled in exactly one place.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size_bytes: int


@dataclass
class ParsedEmail:
    raw_message: Message
    subject: str | None
    date: str | None
    message_id: str | None

    from_display_name: str
    from_addr: str
    reply_to_addrs: list[str]
    to_addrs: list[str]

    auth_results_headers: list[str]
    received_headers: list[str]
    return_path: str | None

    body_text: str
    body_html: str

    attachments: list[Attachment] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        """Case-insensitive single-header lookup, or None if absent."""
        return self.raw_message.get(name)

    def all_headers(self, name: str) -> list[str]:
        """Case-insensitive multi-header lookup (e.g. Received, Authentication-Results)."""
        return [str(v) for v in self.raw_message.get_all(name, [])]


def parse_eml_bytes(data: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return _build_parsed_email(msg)


def parse_eml_file(path: str | os.PathLike) -> ParsedEmail:
    with open(path, "rb") as fp:
        msg = BytesParser(policy=policy.default).parse(fp)
    return _build_parsed_email(msg)


def _build_parsed_email(msg: Message) -> ParsedEmail:
    from_display_name, from_addr = parseaddr(msg.get("From", ""))
    reply_to_addrs = [addr for _, addr in getaddresses(msg.get_all("Reply-To", []))]
    to_addrs = [addr for _, addr in getaddresses(msg.get_all("To", []))]

    body_text, body_html = _extract_bodies(msg)
    attachments = _extract_attachments(msg)

    return ParsedEmail(
        raw_message=msg,
        subject=msg.get("Subject"),
        date=msg.get("Date"),
        message_id=msg.get("Message-ID"),
        from_display_name=from_display_name,
        from_addr=from_addr.lower(),
        reply_to_addrs=[a.lower() for a in reply_to_addrs],
        to_addrs=[a.lower() for a in to_addrs],
        auth_results_headers=[str(v) for v in msg.get_all("Authentication-Results", [])],
        received_headers=[str(v) for v in msg.get_all("Received", [])],
        return_path=msg.get("Return-Path"),
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
    )


def _extract_bodies(msg: Message) -> tuple[str, str]:
    """Return (plaintext, html) bodies, decoded to str. Either may be empty."""
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        plain_part = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))
        if plain_part is not None:
            body_text = _get_content_safe(plain_part)
        if html_part is not None:
            body_html = _get_content_safe(html_part)
    else:
        content_type = msg.get_content_type()
        content = _get_content_safe(msg)
        if content_type == "text/html":
            body_html = content
        else:
            body_text = content

    return body_text, body_html


def _get_content_safe(part: Message) -> str:
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            content = payload.decode(charset, errors="replace")
        except (LookupError, TypeError):
            content = payload.decode("utf-8", errors="replace")
    return content if isinstance(content, str) else str(content)


def _extract_attachments(msg: Message) -> list[Attachment]:
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0
        attachments.append(
            Attachment(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size_bytes=size,
            )
        )
    return attachments

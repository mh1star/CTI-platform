"""محلِّلات النصوص والسجلات: استخراج نص قابل للتحليل من TXT/JSONL/Logs.

- extract_text: TXT عادي، سجل بنسخ logwatch/syslog/nginx/WAF، أو JSONL أحداث.
- تُحفظ الأسماء المميزة من كل سجل (host/process/source_ip) كسطور سياق نصي
  لتغذي محرك الاستخراج بالنطاقات ذات المعنى.
"""

from __future__ import annotations

import io
import json
import re

from app.parsers.pdf_reader import extract_pdf_text

LOGGER_FIELDS = ["source_ip", "src_ip", "client_ip", "remote_addr", "dst_ip", "host",
                 "user_agent", "uri", "url", "signature", "alert", "event_type",
                 "rule", "plugin", "process", "file_name", "md5", "sha256", "cve"]

JSONL_SPLIT_RE = re.compile(r"\]\s*\n|}\s*\n|\]\s*$")


def extract_text(data: bytes, filename: str = "", mime: str = "") -> tuple[str, str]:
    """يُرجع (نص مستخرج، صيغة المصدر)."""
    fname = (filename or "").lower()
    if fname.endswith(".pdf") or mime == "application/pdf":
        return extract_pdf_text(data), "pdf"
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")

    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return _jsonl_to_text(data), "jsonl"
        except Exception:
            pass
    if fname.endswith((".log", ".txt")) and ("json" in fname or _looks_jsonl(text)):
        try:
            return _jsonl_to_text(data), "jsonl"
        except Exception:
            pass
    return text, "text"


def _jsonl_to_text(data: bytes) -> str:
    payload = data.decode("utf-8", errors="replace").strip()
    if payload.startswith("["):
        payload = payload[1:]
    lines: list[str] = []
    for raw in payload.splitlines():
        raw = raw.strip().rstrip(",")
        if not raw or raw in {"[", "]", "{", "}"}:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            lines.append(raw)
            continue
        if isinstance(rec, dict):
            lines.append(_flatten_record(rec))
    return "\n".join(lines)


def _flatten_record(rec: dict) -> str:
    parts: list[str] = []
    for k, v in rec.items():
        if isinstance(v, dict):
            parts.append(_flatten_record(v))
        elif isinstance(v, list):
            parts.append(_flatten_record({str(i): x for i, x in enumerate(v)}))
        else:
            parts.append(f"{k}: {v}")
    return " ".join(parts)


def _looks_jsonl(text: str) -> bool:
    for line in text.strip().splitlines()[:20]:
        line = line.strip()
        if line.startswith("{") and line.rstrip().endswith("}"):
            return True
    return False


def line_preserving_concat(text: str, max_chars: int = 500_000) -> str:
    return text[:max_chars] if len(text) > max_chars else text
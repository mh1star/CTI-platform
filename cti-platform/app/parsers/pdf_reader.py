"""قراءة ملفات PDF واستخلاص النص منها عبر pypdf (مع بديل احتياطي بسيط)."""

from __future__ import annotations

import re

try:
    from pypdf import PdfReader
    HAVE_PYPDF = True
except Exception:  # pragma: no cover - راجع عدم توفر المكتبة
    HAVE_PYPDF = False


def extract_pdf_text(data: bytes) -> str:
    if HAVE_PYPDF:
        try:
            reader = PdfReader(io_bytes(data))
            pages = []
            for page in reader.pages:
                try:
                    pages.append(page.extract_text() or "")
                except Exception:
                    pages.append("")
            return "\n\n".join(pages)
        except Exception:
            pass
    return _crude_pdf_text(data)


def io_bytes(data: bytes):
    import io

    return io.BytesIO(data)


_PDF_TEXT_RE = re.compile(rb"\((?:[^()\\]|\\.)*\)")


def _crude_pdf_text(data: bytes) -> str:
    """استخراج بدائي لدوال Tj/TJ من تدفقات PDF (احتياطي عند غياب pypdf)."""
    out: list[str] = []
    for match in _PDF_TEXT_RE.finditer(data):
        token = match.group(0)[1:-1]
        try:
            token = token.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
            text = token.decode("latin-1", errors="replace")
        except Exception:
            text = ""
        if text.strip():
            out.append(text)
    return "\n".join(out)
"""استخراج مؤشرات الاختراق الحتمية (regex-based) عبر نصوص المنصة."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IPV6_RE = re.compile(
    r"\b(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})"
    r"|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))\b"
)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?!.*\.\d{1,3}\.\d{1,3}$)([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
WINDOWS_PATH_RE = re.compile(r"\b(?:[A-Z]:[\\/]|[\\/]{2})[^\s\"'<>]+", re.IGNORECASE)
FILE_EXT_RE = re.compile(r"\b[\w.\-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|jse|vbe|wsf|hta|scr|pif|jar|msi|apk)\b", re.IGNORECASE)

# لاحقات نطاقات محتملة عامة وامتدادات ملفات تُستبعد من DOMAIN لتجنب النتائج الخاطئة
COMMON_WORDS = {
    "the", "com", "org", "net", "and", "for", "with", "url", "http", "https",
    "example", "domain", "company", "site", "your", "my", "test", "mail",
    "web", "server", "login", "secure", "account", "online", "click",
    "verify", "news", "blog", "store", "help", "info", "home", "www",
}
_FILE_TLDS = {
    "exe", "dll", "zip", "rar", "7z", "pdf", "doc", "docx", "ppt", "pptx", "xls",
    "xlsx", "js", "jar", "ps1", "sh", "apk", "ipa", "bin", "py", "json", "yml",
    "yaml", "csv", "txt", "md", "htm", "html", "png", "jpg", "jpeg", "gif",
    "svg", "iso", "bat", "cmd", "vbs", "msi", "lnk", "tmp", "log", "wav",
    "mp3", "mp4", "com", "so", "pak", "dat", "ini", "xml", "db", "sql",
}


def _normalize(value: str) -> str:
    return value.rstrip(".,;:!?)")


@dataclass
class IOC:
    type: str
    value: str
    start: int
    end: int
    confidence: float = 1.0


def extract_iocs(text: str) -> list[IOC]:
    found: list[IOC] = []
    tail = text

    def add(match: re.Match[str], type_: str, confidence: float = 1.0) -> None:
        value = _normalize(match.group(0))
        if not value:
            return
        found.append(IOC(type=type_, value=value, start=match.start(),
                         end=match.start() + len(value), confidence=confidence))

    for m in CVE_RE.finditer(tail):
        add(m, "CVE")
    for m in CWE_RE.finditer(tail):
        add(m, "CWE", 0.9)
    for m in URL_RE.finditer(tail):
        add(m, "URL")
    for m in EMAIL_RE.finditer(tail):
        add(m, "EMAIL")
    for m in SHA256_RE.finditer(tail):
        add(m, "HASH_SHA256")
    for m in SHA1_RE.finditer(tail):
        add(m, "HASH_SHA1")
    for m in MD5_RE.finditer(tail):
        add(m, "HASH_MD5")
    for m in IPV4_RE.finditer(tail):
        value = m.group(0)
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                add(m, "IP", confidence=0.98)
            else:
                add(m, "IP")
        except ValueError:
            continue
    for m in IPV6_RE.finditer(tail):
        try:
            ipaddress.ip_address(m.group(0))
            add(m, "IP")
        except ValueError:
            continue
    for m in DOMAIN_RE.finditer(tail):
        value = _normalize(m.group(0))
        labels = value.split(".")
        tld = labels[-1].lower()
        if tld in _FILE_TLDS:
            continue
        if tld in COMMON_WORDS and len(labels) == 2 and labels[0].lower() in COMMON_WORDS:
            continue
        add(m, "DOMAIN")
    for m in WINDOWS_PATH_RE.finditer(tail):
        add(m, "FILE_PATH", 0.7)
    for m in FILE_EXT_RE.finditer(tail):
        value = _normalize(m.group(0))
        add(m, "FILE_NAME", 0.85)

    # إزالة التداخلات: إبقاء الأكثر تحديداً (الأطول) عند تعارض النطاقات
    merged = sorted(found, key=lambda x: (x.start, -(x.end - x.start)))
    result: list[IOC] = []
    for item in merged:
        if result and item.start < result[-1].end:
            prev = result[-1]
            # نطاق أطول يحل محل الأقصر في المنزلق نفسه
            if (item.end - item.start) > (prev.end - prev.start):
                result[-1] = item
            continue
        result.append(item)
    return result
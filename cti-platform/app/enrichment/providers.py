"""مزوّدو الإثراء الخارجيون: VirusTotal, AbuseIPDB, AlienVault OTX.

يتم الاستعلام عبر urllib القياسي (بدون اعتماديات إضافية)، مع مهلة زمنية،
وإحباط نيابي عند غياب مفتاح، وإنتاج نتيجة موحّدة (score/verdict/detail).
"""

from __future__ import annotations

import json
import ssl
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Callable

from app.config import settings
from app.enrichment.offline_db import lookup_offline

HEADERS = {"User-Agent": "CTI-Security-Platform/1.0 (+academic)"}
TIMEOUT = settings.http_timeout


def _get_json(url: str, key_header: str | None = None, key: str | None = None) -> dict | None:
    req = urllib.request.Request(url, headers=HEADERS)
    if key_header and key:
        req.add_header(key_header, key)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _score_from_counts(stats: dict, kind: str) -> tuple[int, str]:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    total = malicious + suspicious + harmless
    if total == 0:
        return 0, "not_found"
    ratio = (malicious * 1.0 + suspicious * 0.5) / total
    score = int(round(ratio * 100))
    if malicious and malicious >= 3 or score >= 75:
        return min(99, score), "malicious"
    if suspicious or score >= 35:
        return min(70, score), "suspicious"
    return max(5, score), "neutral"


VT_PATH = {
    "IP": "ip_addresses",
    "ipv6": "ip_addresses",
    "DOMAIN": "domains",
    "URL": "urls",
    "HASH_SHA256": "files",
    "HASH_SHA1": "files",
    "HASH_MD5": "files",
}


def query_virustotal(value: str, type_: str) -> dict[str, object] | None:
    if not settings.vt_key:
        return None
    path = VT_PATH.get(type_)
    if not path:
        return None
    if type_ == "URL":
        value = urllib.parse.quote_plus(value)
    url = f"https://www.virustotal.com/api/v3/{path}/{urllib.parse.quote(value)}"
    data = _get_json(url, key_header="x-apikey", key=settings.vt_key) or {}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    score, verdict = _score_from_counts(stats, "vt")
    names = attrs.get("names") or []
    return {
        "provider": "VirusTotal",
        "score": score,
        "verdict": verdict,
        "detail": f"مراجعات: {stats.get('malicious', 0)} خبيثة / {stats.get('suspicious', 0)} مشبوهة / {stats.get('harmless', 0)} سليمة",
        "first_seen": attrs.get("first_seen_date") or attrs.get("first_submission_date") or None,
        "source_url": f"https://www.virustotal.com/gui/{path.rstrip('s')}/{urllib.parse.quote(value)}",
        "quoted_at": datetime.now(UTC).isoformat(),
    }


def query_abuseipdb(value: str, type_: str) -> dict[str, object] | None:
    if not settings.abuseipdb_key or type_ not in {"IP", "ipv6"}:
        return None
    params = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
    url = f"https://api.abuseipdb.com/api/v2/check?{params}"
    try:
        data = _get_json(url, key_header="Key", key=settings.abuseipdb_key) or {}
        rec = data.get("data") or {}
        score = int(rec.get("abuseConfidenceScore", 0) or 0)
        verdict = "malicious" if score >= 60 else ("suspicious" if score >= 30 else "neutral")
        domains = rec.get("domains") or []
        return {
            "provider": "AbuseIPDB",
            "score": score,
            "verdict": verdict,
            "detail": f"درجة الائتمان: {score} | الاستخدام: {rec.get('usageType') or 'غير محدد'} | النطاقات: {len(domains)}",
            "country": rec.get("countryCode"),
            "isp": rec.get("isp"),
            "source_url": f"https://www.abuseipdb.com/check/{value}",
            "quoted_at": datetime.now(UTC).isoformat(),
        }
    except Exception:
        return None


OTX_TYPE = {
    "IP": "IPv4",
    "ipv6": "IPv6",
    "DOMAIN": "domain",
    "URL": "url",
    "HASH_SHA256": "file",
    "HASH_SHA1": "file",
    "HASH_MD5": "file",
}


def query_otx(value: str, type_: str) -> dict[str, object] | None:
    if not settings.otx_key:
        return None
    otx_t = OTX_TYPE.get(type_)
    if not otx_t:
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_t}/{urllib.parse.quote(value)}/general"
    try:
        data = _get_json(url, key_header="X-OTX-API-KEY", key=settings.otx_key) or {}
        pulse = data.get("pulse_info") or {}
        pulses = pulse.get("pulses") or []
        count = len(pulses)
        score = min(99, 20 * count) if count else 0
        verdict = "malicious" if score >= 60 else ("suspicious" if score >= 30 else "neutral")
        tags = list({t for p in pulses for t in (p.get("tags") or [])})
        return {
            "provider": "AlienVault OTX",
            "score": score,
            "verdict": verdict,
            "detail": f"نبضات مرتبطة: {count} | الوسوم: {', '.join(tags[:6]) or 'لا يوجد'}",
            "count": count,
            "source_url": f"https://otx.alienvault.com/indicator/{otx_t}/{value}",
            "quoted_at": datetime.now(UTC).isoformat(),
        }
    except Exception:
        return None


PROVIDER_QUERIES: dict[str, list[Callable[[str, str], dict[str, object] | None]]] = {
    "IP": [query_virustotal, query_abuseipdb, query_otx],
    "ipv6": [query_abuseipdb, query_otx],
    "DOMAIN": [query_virustotal, query_otx],
    "URL": [query_virustotal, query_otx],
    "HASH_SHA256": [query_virustotal, query_otx],
    "HASH_SHA1": [query_virustotal, query_otx],
    "HASH_MD5": [query_virustotal, query_otx],
}


def aggregate(value: str, type_: str, with_offline: bool = True) -> list[dict[str, object]]:
    """يجمع نتائج كل المزوّدين المكوّنين إضافة إلى النتيجة غير المتصلة."""

    def to_offline(verdict: str, score: int, detail: str) -> dict[str, object]:
        return {
            "provider": "Offline Intelligence DB",
            "score": score, "verdict": verdict, "detail": detail,
            "source_url": "", "quoted_at": datetime.now(UTC).isoformat(),
        }

    offline = lookup_offline(value, type_) if with_offline else None
    results: list[dict[str, object]] = []
    if offline:
        results.append(to_offline(offline["verdict"], offline["score"], offline["detail"]))
    for q in PROVIDER_QUERIES.get(type_, []):
        try:
            res = q(value, type_)
        except Exception:
            res = None
        if res:
            results.append(res)
    return results
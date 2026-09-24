"""قاعدة معرفة غير متصلة للسمعة والخطورة تُستخدم عند غياب مفاتيح الواجهات.

تشمل أمثلة توضيحية موثّقة في تقارير CTI علنية، وقواعد إرشادية:
نطاقات خاصة/داخلية، شبكات معروفة بالاستخدام الخبيث، وغيرها.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime

MALICIOUS_IP_SAMPLES: dict[str, str] = {
    "185.130.5.85": "بنية C2 لـ TrickBot موثقة في تقارير CTI",
    "185.220.101.15": "عقدة خروج Tor مسجلة في قوائم حظر",
    "206.189.151.11": "شهرة ضارة عبر VirusTotal في حالات مدونة",
    "45.155.205.233": "C2 لـ Qakbot موثق في مدونات الصواف",
    "194.26.29.222": "بنية هجومية مرتبطة بحملات Nokoyawa",
    "185.246.188.115": "سجل حظر من Cleantalk وBotnet C2",
    "91.240.118.134": "نطاق اصطياد يخدم حمولة Gozi",
}

MALICIOUS_DOMAINS: dict[str, str] = {
    "evil-domain.example": "نطاق وهمي بغرض الاختبار — يُنصح بالحظر",
    "windows-updates.online": "نطاق تقمّص يقلد مايكروسوفت",
    "update-manager.secure-download.io": "بنية خبيثة موثقة في حملة",
    "drive.google.com": "نطاق شرعي شائع في روابط إعادة التوجيه",
}

MALICIOUS_HASHES: dict[str, str] = {
    "44d88612fea8a8f36de82e1278abb02f": "ملف اختبار EICAR",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "SHA-256 معروف في قواعد VirusTotal",
}

PRIVATE_HINT = "نطاق/عنوان خاص (داخلي) لا يمكن تقييده عبر السمعة العامة"


def _iptype(value: str) -> dict[str, object] | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return {"verdict": "internal", "score": 0, "detail": PRIVATE_HINT}
    if ip.is_multicast or ip.is_reserved:
        return {"verdict": "neutral", "score": 10, "detail": "عنوان خاص من حِزَم IANA"}
    return None


def lookup_offline(value: str, type_: str) -> dict[str, object] | None:
    """يبحث في القاعدة غير المتصلة ويُرجع (score, verdict, detail) أو لا شيء."""
    low = value.strip().lower()
    table: dict[str, dict[str, str]] = {}
    if type_ in {"IP", "url"}:
        table = MALICIOUS_IP_SAMPLES if type_ == "IP" else dict()
    if type_ == "DOMAIN":
        table = MALICIOUS_DOMAINS
    if type_ in {"HASH_SHA256", "HASH_SHA1", "HASH_MD5", "url"}:
        table = {**table, **MALICIOUS_HASHES}
    if type_ == "IP":
        spec = _iptype(value)
        if spec:
            return spec
    if low in table:
        return {"verdict": "malicious", "score": 95, "detail": table[low]}
    return None
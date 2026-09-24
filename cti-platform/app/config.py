"""مركز الإعدادات: مفاتيح واجهات الإثراء ونسبها."""

from __future__ import annotations

import os


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


class Settings:
    title: str = "CTI Security Intelligence Platform"
    version: str = "1.0.0"
    description: str = "منصة استخبارات تهديدات أمنية متكاملة: استخراج كيانات عبر NER، إثراء تلقائي، MITRE ATT&CK، وتصدير STIX 2.1."

    vt_key: str = _env("CTI_VT_KEY")
    abuseipdb_key: str = _env("CTI_ABUSEIPDB_KEY")
    otx_key: str = _env("CTI_OTX_KEY")

    reputation_cache_ttl: int = int(_env("CTI_CACHE_TTL", "900"))
    http_timeout: float = float(_env("CTI_HTTP_TIMEOUT", "6.0"))
    data_dir: str = _env("CTI_DATA_DIR", "data")

    @property
    def enrichment_providers(self) -> dict[str, bool]:
        return {
            "virustotal": bool(self.vt_key),
            "abuseipdb": bool(self.abuseipdb_key),
            "alienvault_otx": bool(self.otx_key),
        }


settings = Settings()
"""مولّد حزمة STIX 2.1 من كيانات التحليل.

يحول كل كيان إلى كائن سرد (SCO/SDO) قياسي ويبني علاقات بينها، ثم يربطها
في Bundle واحد جاهز للمشاركة مع أنظمة SIEM/TAXII.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Iterable

from app.ner.extractor import Entity

NAMESPACE = uuid.UUID("67a64d5c-4f1a-4b1a-9d1a-840d0e5b1c39")

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"


def _now() -> str:
    return datetime.now(UTC).strftime(TIME_FORMAT)


def _uid(kind: str, key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{kind}:{key}"))


def _stix_id(kind: str, key: str) -> str:
    return f"{kind}--{_uid(kind, key)}"


def _ts() -> str:
    return _now()


def build_bundle(entities: list[Entity], report_meta: dict[str, object] | None = None) -> dict[str, object]:
    now = _ts()
    bundle_id = _stix_id("bundle", f"{now}:{uuid.uuid4()}")
    objects: list[dict[str, object]] = []

    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity", "cti-platform"),
        "created": now,
        "modified": now,
        "name": "CTI Security Intelligence Platform",
        "identity_class": "organization",
        "description": "منصة استخبارات تهديدات أكاديمية — مولِّد تلقائي لبيانات STIX.",
        "labels": ["threat-intel"],
    }
    objects.append(identity)

    def add(obj: dict[str, object]) -> str:
        objects.append(obj)
        return str(obj["id"])

    entity_ids: dict[int, str] = {}

    for ent in entities:
        key = f"{ent.type}:{ent.value}"
        oid = _stix_id("indicator", key)
        entity_ids[ent.id] = oid
        labels: list[str] = ["malicious-activity"] if ent.type in {"MALWARE", "GROUP", "VULN"} else [ent.type.lower()]

        obj: dict[str, object] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": oid,
            "created": now,
            "modified": now,
            "name": str(ent.value),
            "description": f"{ent.type} المستخرج من التحليل | الثقة {round(ent.confidence * 100)}%",
            "indicator_types": ["malicious-activity"],
            "pattern": _to_pattern(ent),
            "pattern_type": "stix",
            "valid_from": now,
            "labels": labels,
            "confidence": int(round(ent.confidence * 100)),
        }
        add(obj)

        # كائنات رصد مقابلة
        obs_id = add(_to_observable(ent, now))

        add({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship", f"{oid}->{obs_id}"),
            "created": now,
            "modified": now,
            "relationship_type": "based-on",
            "source_ref": oid,
            "target_ref": obs_id,
        })

        # كائنات سرد دلالية
        if ent.type == "MALWARE":
            ref = add({
                "type": "malware", "spec_version": "2.1",
                "id": _stix_id("malware", key),
                "created": now, "modified": now,
                "name": str(ent.value),
                "is_family": False,
                "labels": ["malware"],
            })
            add({"type": "relationship", "spec_version": "2.1",
                 "id": _stix_id("relationship", f"{oid}->{ref}"),
                 "created": now, "modified": now, "relationship_type": "indicates",
                 "source_ref": oid, "target_ref": ref})
        elif ent.type == "GROUP":
            ref = add({
                "type": "threat-actor", "spec_version": "2.1",
                "id": _stix_id("threat-actor", key),
                "created": now, "modified": now,
                "name": str(ent.value),
                "threat_actor_types": ["crime-syndicate"],
            })
            add({"type": "relationship", "spec_version": "2.1",
                 "id": _stix_id("relationship", f"{oid}->{ref}"),
                 "created": now, "modified": now, "relationship_type": "indicates",
                 "source_ref": oid, "target_ref": ref})
        elif ent.type == "CVE" or ent.type == "VULN":
            ref = add({
                "type": "vulnerability", "spec_version": "2.1",
                "id": _stix_id("vulnerability", key),
                "created": now, "modified": now,
                "name": str(ent.value),
                "external_references": [{"source_name": "NVD", "external_id": str(ent.value)}],
            })
            add({"type": "relationship", "spec_version": "2.1",
                 "id": _stix_id("relationship", f"{oid}->{ref}"),
                 "created": now, "modified": now, "relationship_type": "indicates",
                 "source_ref": oid, "target_ref": ref})

        # ربط MITRE: نقلة هجوم من الكيان الملوث
        for m in ent.mitre:
            tid = str(m.get("id", ""))
            if not tid:
                continue
            ap_id = _stix_id("attack-pattern", tid)
            objects.append({
                "type": "attack-pattern", "spec_version": "2.1",
                "id": ap_id, "created": now, "modified": now,
                "name": str(m.get("name", tid)),
                "external_references": [{"source_name": "mitre-attack",
                                         "external_id": tid,
                                         "url": f"https://attack.mitre.org/techniques/{tid.split('.')[0]}/"}],
            })
            add({"type": "relationship", "spec_version": "2.1",
                 "id": _stix_id("relationship", f"{oid}->{ap_id}"),
                 "created": now, "modified": now, "relationship_type": "indicates",
                 "source_ref": oid, "target_ref": ap_id})

        # روابط الاستفادة الطبيعية: CVE → MALWARE
        if ent.type in {"CVE", "VULN"}:
            for other in entities:
                if other.type == "MALWARE" and other.id != ent.id and _near(ent, other, 120):
                    o_ref = _stix_id("vulnerability", f"{other.type}:{other.value}")
                    add({"type": "relationship", "spec_version": "2.1",
                         "id": _stix_id("relationship", f"{oid}->{o_ref}"),
                         "created": now, "modified": now,
                         "relationship_type": "exploits",
                         "source_ref": oid, "target_ref": o_ref})

    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "id": bundle_id,
        "objects": objects,
    }
    if report_meta:
        bundle["meta"] = report_meta
    return bundle


def _near(a: Entity, b: Entity, distance: int) -> bool:
    return abs(a.start - b.start) <= distance


def _to_pattern(ent: Entity) -> str:
    kind = ent.type
    v = str(ent.value).replace("'", "\\\\'")
    if kind in {"IP", "ipv6"}:
        return f"[ipv4-addr:value = '{v}']"
    if kind == "DOMAIN":
        return f"[domain-name:value = '{v}']"
    if kind == "URL":
        return f"[url:value = '{v}']"
    if kind == "EMAIL":
        return f"[email-addr:value = '{v}']"
    if kind == "CVE":
        return f"[vulnerability:name = '{v}']"
    if kind == "HASH_MD5":
        return f"[file:hashes.MD5 = '{v}']"
    if kind == "HASH_SHA1":
        return f"[file:hashes.SHA-1 = '{v}']"
    if kind in {"HASH_SHA256", "HASH_SHA1", "HASH_MD5"}:
        return f"[file:hashes.SHA-256 = '{v}']"
    return f"[x-cti:{kind.lower()} = '{v}']"


def _to_observable(ent: Entity, now: str) -> dict[str, object]:
    kind = ent.type
    v = str(ent.value)
    base = {"spec_version": "2.1", "created": now, "modified": now}
    if kind in {"IP", "ipv6"}:
        return {"type": "ipv4-addr", "id": _stix_id("ipv4-addr", f"{kind}:{v}"), **base, "value": v}
    if kind == "DOMAIN":
        return {"type": "domain-name", "id": _stix_id("domain-name", v), **base, "value": v}
    if kind == "URL":
        return {"type": "url", "id": _stix_id("url", v), **base, "value": v}
    if kind == "EMAIL":
        return {"type": "email-addr", "id": _stix_id("email-addr", v), **base, "value": v}
    if kind == "HASH_MD5":
        return {"type": "file", "id": _stix_id("file", v), **base, "hashes": {"MD5": v}}
    if kind == "HASH_SHA1":
        return {"type": "file", "id": _stix_id("file", v), **base, "hashes": {"SHA-1": v}}
    if kind == "HASH_SHA256":
        return {"type": "file", "id": _stix_id("file", v), **base, "hashes": {"SHA-256": v}}
    return {"type": "indicator", "id": _stix_id("indicator", f"{kind}:{v}"),
            "name": v, **base}
"""مولّد رسم بياني معرفي (Knowledge Graph) من نتائج التحليل.

يُرجع عقداً (nodes) بحسب فئة الكيان وحوافاً (edges/links) معقّلة بالمعنى:
- تلاقٍ في نفس السجل/الفقرة ⇒ حافة "co-occur"
- ظهور MITRE من كيان ⇒ حافة "maps_to"
- برمجية خبيثة ← ثغرة قريبة ⇒ حافة "exploits"
- عنوان/نطاق محيط ببرمجية ⇒ حافة "related_infrastructure"
"""

from __future__ import annotations

from typing import Iterable

from app.ner.extractor import Entity

DISTANCE = 220

COLORS = {
    "IP": "#22d3ee", "DOMAIN": "#60a5fa", "URL": "#818cf8", "EMAIL": "#c084fc",
    "CVE": "#f87171", "CWE": "#fb923c", "MALWARE": "#f472b6", "TECHNIQUE": "#4ade80",
    "GROUP": "#facc15", "VULN": "#fb7185", "HASH_SHA256": "#34d399",
    "HASH_SHA1": "#34d399", "HASH_MD5": "#34d399", "FILE_PATH": "#a3a3a3",
    "FILE_NAME": "#a3a3a3", "SOFTWARE": "#94a3b8", "CAMPAIGN": "#e879f9",
}

LANE_ORDER = ["GROUP", "CAMPAIGN", "TECHNIQUE", "MALWARE", "VULN", "CVE", "CWE"]
INFRA_LANES = ["IP", "DOMAIN", "URL", "EMAIL", "HASH_SHA256", "HASH_SHA1", "HASH_MD5", "FILE_PATH", "FILE_NAME"]


def build_graph(entities: list[Entity], text: str | None = None) -> dict[str, object]:
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    node_by_id: dict[int, dict[str, object]] = {}

    for ent in entities:
        node = {
            "id": ent.id,
            "type": ent.type,
            "label": ent.value,
            "color": COLORS.get(ent.type, "#94a3b8"),
            "confidence": round(ent.confidence, 4),
            "source": ent.sources[0],
            "start": ent.start,
            "end": ent.end,
            "mitre": [m.get("id") for m in ent.mitre],
        }
        nodes.append(node)
        node_by_id[ent.id] = node

    ents = sorted(entities, key=lambda e: e.start)
    seen_edges: set[tuple[int, int, str]] = set()

    def edge(a: int, b: int, kind: str) -> None:
        lo, hi = (a, b) if a < b else (b, a)
        if lo == hi:
            return
        key = (lo, hi, kind)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append({"source": lo, "target": hi, "relation": kind})

    # حواف التلاقي بين الكيانات القريبة
    for i, a in enumerate(ents):
        for b in ents[i + 1:]:
            if b.start - a.end > DISTANCE:
                break
            if a.type == b.type:
                continue
            edge(a.id, b.id, "co-occur")

    # خريطة الاستفادة: برمجية متعلقة بثغرة/نقطة ضعف قريبة
    malwares = [e for e in ents if e.type == "MALWARE"]
    vulns = [e for e in ents if e.type in {"CVE", "VULN", "CWE"}]
    for m in malwares:
        for v in vulns:
            if abs(m.start - v.start) <= DISTANCE:
                edge(m.id, v.id, "exploits")
        for t_id in _flatten_mitre(m):
            for e in ents:
                if t_id in e.mitre_ids():
                    edge(m.id, e.id, "maps_to")

    # روابط بنية تحتية (منطقة/مجال/تجزئة) قريبة من برمجية أو مجموعة
    for a in ents:
        if a.type not in INFRA_LANES:
            continue
        for b in ents:
            if b.type not in {"MALWARE", "GROUP", "VULN", "CVE"}:
                continue
            if abs(a.start - b.start) <= DISTANCE:
                edge(a.id, b.id, "related_infrastructure")

    # ربط تقنية بتقنيات MITRE المرتبطة تحت منطقة المجموعة/البرمجية الكبرى (تجميعي)
    mitre_map: dict[str, list[int]] = {}
    for e in ents:
        if e.mitre:
            for m in e.mitre:
                tid = str(m.get("id", ""))
                mitre_map.setdefault(tid, []).append(e.id)
    for tid, owner_ids in mitre_map.items():
        for oid in owner_ids:
            for tid2, other_ids in mitre_map.items():
                if tid == tid2 or oid in other_ids:
                    continue
                edge(oid, other_ids[0], "shared_technique")

    return {"nodes": nodes, "edges": edges}


def _flatten_mitre(e: Entity) -> list[str]:
    return [str(m.get("id", "")) for m in e.mitre if m.get("id")]
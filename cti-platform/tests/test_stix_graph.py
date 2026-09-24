"""اختبارات تصدير STIX 2.1 و الرسم البياني المعرفي."""

from app.graph.builder import build_graph
from app.ner.extractor import Entity
from app.stix.builder import build_bundle


def _entity(eid, etype, value, start, end, confidence=0.9, mitre=None):
    return Entity(id=eid, type=etype, value=value, confidence=confidence,
                  start=start, end=end, mitre=mitre or [])


def test_stix_bundle_shape():
    ent = _entity(0, "IP", "185.130.5.85", 10, 22, mitre=[{"id": "T1071", "name": "Application Layer Protocol"}])
    bundle = build_bundle([ent], {"request_id": "r1", "source": "test"})
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    objs = bundle["objects"]
    assert any(o["type"] == "identity" for o in objs)
    inds = [o for o in objs if o["type"] == "indicator"]
    assert inds and "pattern" in inds[0]
    assert any(o["type"] == "attack-pattern" for o in objs)
    assert any(o["type"] == "relationship" for o in objs)


def test_stix_malware_sdo():
    ent = _entity(1, "MALWARE", "Emotet", 0, 6)
    bundle = build_bundle([ent])
    malware = [o for o in bundle["objects"] if o["type"] == "malware"]
    assert malware and malware[0]["name"] == "Emotet"


def test_graph_lanes_and_cooc():
    a = _entity(0, "GROUP", "APT29", 0, 8)
    b = _entity(1, "MALWARE", "Emotet", 12, 18)
    c = _entity(2, "IP", "185.130.5.85", 30, 42)
    g = build_graph([a, b, c])
    nodes = {n["id"]: n for n in g["nodes"]}
    assert len(g["nodes"]) == 3
    assert nodes[0]["type"] == "GROUP" and nodes[0]["color"]
    rels = {e["relation"] for e in g["edges"]}
    assert "co-occur" in rels
    # عقدة GROUP/MALWARE قريبة تتصل بالبنية التحتية عند البعد المنخفض
    assert any(e["relation"] == "related_infrastructure" for e in g["edges"])
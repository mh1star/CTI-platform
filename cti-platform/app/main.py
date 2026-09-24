"""واجهة REST API لمنصة استخبارات التهديدات الأمنية (CTI Platform).

يحمّل النموذج ويقيّمه عند بدء التشغيل (دورة تدريب حقيقية على مجموعة CTI معنونة)،
ويوفر نقاط استخراج، إثراء، MITRE، رسم بياني، وتصدير STIX 2.1.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.enrichment.providers import aggregate as aggregate_reputation
from app.graph.builder import COLORS, build_graph
from app.models import AnalysisResponse, AnalysisSummary, EvalResponse, ReputationRequest, ReputationResponse, TextRequest
from app.ner.extractor import TYPE_DISPLAY, Extractor
from app.ner.features import tokens_only
from app.parsers.text_parsers import extract_text, line_preserving_concat
from app.runtime import build_model, evaluate_result, get_model
from app.stix.builder import build_bundle

app = FastAPI(
    title=settings.title,
    version=settings.version,
    description=settings.description + " نوع المخرجات: STIX 2.1 / Knowledge Graph.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# محرك الاستخراج يُبنى عند أول طلب بعد اكتمال التدريب (تأخير بارد منفصل).
_engine: Extractor | None = None
_reputation_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _get_engine() -> Extractor:
    global _engine
    if _engine is None:
        _engine = Extractor(get_model())
    return _engine


@app.on_event("startup")
def _startup() -> None:
    build_model()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cti-security-intelligence-platform",
            "model": "trained" if get_model() is not None else "ready"}


@app.get("/api/model/info")
def model_info() -> dict[str, object]:
    tg = get_model()
    return {
        "engine": tg.algorithm_name,
        "algorithm": tg.describe(),
        "upgrade_path": "SecBERT/CyNER fine-tune (HuggingFace) compatible — see README",
        "trained_at": evaluate_result().get("trained_at"),
    }


@app.get("/api/eval", response_model=EvalResponse)
def evaluation() -> EvalResponse:
    data = evaluate_result()
    return EvalResponse(
        model=data["model"],
        dataset=data["dataset"],
        token_level=data["token_level"],
        span_level=data["span_level"],
        pipeline=data.get("pipeline", {}),
        n_test_records=data["n_test_records"],
        n_tokens=data["n_tokens"],
        training_seconds=data.get("training_seconds", 0),
        train_records=data.get("train_records", 0),
        trained_at=data.get("trained_at", ""),
    )


@app.get("/api/entities")
def entity_types() -> dict[str, object]:
    return {"types": TYPE_DISPLAY, "colors": COLORS}


@app.get("/api/mitre/techniques")
def mitre_list(q: str | None = Query(default=None), limit: int = Query(default=30, le=200)) -> dict[str, object]:
    from app.mitre.knowledge import TECHNIQUES, search

    if q:
        results = search(q, limit=limit)
    else:
        results = [{"id": tid, "name": meta["name"], "tactics": meta["tactics"]}
                   for tid, meta in sorted(TECHNIQUES.items())][:limit]
    return {"count": len(results), "results": results}


@app.get("/api/mitre/technique/{tech_id}")
def mitre_detail(tech_id: str) -> dict[str, object]:
    from app.mitre.knowledge import TECHNIQUES

    hit = TECHNIQUES.get(tech_id.upper())
    if not hit:
        raise HTTPException(status_code=404, detail="النقلة غير موجودة.")
    return {"id": tech_id.upper(), **hit}


@app.get("/api/enrichment/providers")
def enrichment_status() -> dict[str, object]:
    return {
        "providers": settings.enrichment_providers,
        "mode": "auto (خارجي عند توفر مفتاح + قاعدة غير متصلة دائماً)",
    }


@app.post("/api/enrichment/reputation", response_model=ReputationResponse)
def reputation(payload: ReputationRequest) -> ReputationResponse:
    key = f"{payload.type.upper()}|{payload.value.strip().lower()}"
    now = time.time()
    cached = _reputation_cache.get(key)
    if cached and (now - cached[0]) < settings.reputation_cache_ttl:
        return ReputationResponse(value=payload.value, type=payload.type, providers=cached[1])
    result = aggregate_reputation(payload.value.strip(), payload.type)
    _reputation_cache[key] = (now, result)
    return ReputationResponse(value=payload.value, type=payload.type, providers=result)


def _run_analysis(text_source: str, text: str, enrich: bool, include_stix: bool) -> dict[str, object]:
    entities = _get_engine().extract(text)
    summarized = _summarize(entities, text)
    graph = build_graph(entities, text)

    if enrich:
        for ent in entities:
            if ent.type in {"IP", "DOMAIN", "URL", "EMAIL", "HASH_SHA256", "HASH_SHA1", "HASH_MD5"}:
                ent.__dict__["reputation"] = _cached_reputation(ent.value, ent.type)
    entity_dicts = [e.to_dict() for e in entities]
    for d, e in zip(entity_dicts, entities):
        if "reputation" in e.__dict__:
            d["reputation"] = e.__dict__["reputation"]

    bundle = None
    if include_stix:
        bundle = build_bundle(entities, {"request_id": text_source, "source": "CTI-platform"})

    return {
        "request_id": str(uuid.uuid4()),
        "text_len": len(text),
        "engine": "fused-regex+NER(Viterbi)",
        "summary": summarized,
        "entities": entity_dicts,
        "graph": graph,
        "stix": bundle,
    }


def _cached_reputation(value: str, type_: str) -> list[dict[str, Any]]:
    key = f"{type_}|{value.strip().lower()}"
    now = time.time()
    cached = _reputation_cache.get(key)
    if cached and (now - cached[0]) < settings.reputation_cache_ttl:
        return cached[1]
    result = aggregate_reputation(value, type_)
    _reputation_cache[key] = (now, result)
    return result


def _summarize(entities, text: str) -> dict[str, object]:
    counts: dict[str, int] = {}
    for e in entities:
        counts[e.type] = counts.get(e.type, 0) + 1
    high = sum(1 for e in entities if e.confidence >= 0.8)
    mitre: list[dict[str, object]] = []
    seen: set[str] = set()
    for e in entities:
        for m in e.mitre:
            mid = str(m.get("id", ""))
            if mid and mid not in seen:
                seen.add(mid)
                mitre.append(m)

    # بتقدير الإجمالي خطر
    risk = "low"
    weights = {"MALWARE": 3, "GROUP": 3, "CVE": 2, "VULN": 2, "IP": 1, "DOMAIN": 1, "URL": 1, "TECHNIQUE": 2}
    score = sum(weights.get(t, 0) for t in counts)
    malicious_reps = 0
    for e in entities:
        for rep in getattr(e, "reputation", []):
            if rep.get("verdict") == "malicious":
                malicious_reps += 1
    score += malicious_reps
    if score >= 12 or (counts.get("MALWARE") and counts.get("CVE")):
        risk = "critical"
    elif score >= 7:
        risk = "high"
    elif score >= 3:
        risk = "medium"
    return {
        "total_entities": len(entities),
        "by_type": counts,
        "risk_level": risk,
        "mitre_techniques": mitre,
        "high_confidence": high,
    }


@app.post("/api/extract", response_model=AnalysisResponse)
def extract(payload: TextRequest) -> AnalysisResponse:
    text = line_preserving_concat(payload.text)
    data = _run_analysis(payload.text[:24], text, payload.enrich, include_stix=True)
    return AnalysisResponse(**data)


@app.post("/api/analyze/pdf")
@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...), enrich: bool = True) -> AnalysisResponse:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="الملف فارغ.")
    text, source_fmt = extract_text(raw, filename=file.filename or "", mime=file.content_type or "")
    text = line_preserving_concat(text)
    if len(text.strip()) < 10:
        raise HTTPException(status_code=422, detail="تعذّر استخراج نص ذي معنى من الملف (قد يكون صورة أو محتوى مشفراً).")
    data = _run_analysis(f"{source_fmt}:{file.filename}", text, enrich, include_stix=True)
    return AnalysisResponse(**data)


@app.post("/api/graph")
def graph_only(payload: TextRequest) -> dict[str, object]:
    entities = _get_engine().extract(payload.text)
    return build_graph(entities, payload.text)


@app.post("/api/stix")
def stix_export(payload: TextRequest) -> dict[str, object]:
    entities = _get_engine().extract(payload.text)
    return build_bundle(entities, {"request_id": str(uuid.uuid4()), "source": "api/export"})


@app.get("/api/sample")
def sample() -> dict[str, object]:
    text = (
        "تحليل هجوم: رصدنا نشاطاً خبيثاً للبرمجية {malware} Emotet يوزع عبر تقنية Phishing من عنوان "
        "185.130.5.85 إلى النطاق evil-domain.example مع رابط https://evil-domain.example/dropper.exe. "
        "ارتبط الهجوم بمجموعة APT29 عبر ثغرة Log4Shell (CVE-2021-44228) واستخدام Mimikatz لاستخراج "
        "بيانات الاعتماد ثم الانتقال الجانبي عبر SMB. ورد ملف تجزئة e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
    )
    return {"text": text, "hint": "نموذج نص متعدد السياقات للاستخراج"}


WEB_DIR = Path(__file__).resolve().parent.parent / "web"
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(str(WEB_DIR / "index.html"))


def main() -> None:
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8010, reload=False)


if __name__ == "__main__":
    main()
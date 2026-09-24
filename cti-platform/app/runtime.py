"""محرّك الدورة التدريبية للواجهة: بناء النموذج وتقييمه وإتاحته للاستدلال."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from app.eval.metrics import evaluate, pipeline_evaluation
from app.ner.crf import CrfTagger
from app.ner.data import load_corpus, load_split, pipeline_corpus
from app.ner.extractor import Extractor

TRAINED_AT = None
TEST_METRICS: dict[str, object] = {}
CORPUS_STATS: dict[str, object] = {}
_LOOKUP: CrfTagger | None = None


def build_model() -> CrfTagger:
    global TRAINED_AT, TEST_METRICS, CORPUS_STATS, _LOOKUP
    train, test = load_split()

    n_tokens = sum(len(words) for words, _ in train)
    n_annotated = sum(1 for _, tags in train for t in tags if t != "O")
    CORPUS_STATS = {
        "train_records": len(train),
        "test_records": len(test),
        "tokens": n_tokens,
        "annotated_tokens": n_annotated,
        "source": "تدريب: قوالب CTI مولّدة موسّعة — اختبار: مجموعة يدوية حقيقية منفصلة",
    }

    start = time.perf_counter()
    tagger = CrfTagger().fit(train)
    fit_ms = int((time.perf_counter() - start) * 1000)

    TEST_METRICS = evaluate(tagger.predict, test)
    TEST_METRICS["training_seconds"] = round(fit_ms / 1000, 3)
    TEST_METRICS["train_records"] = len(train)
    TEST_METRICS["test_records"] = len(test)
    TEST_METRICS["pipeline"] = pipeline_evaluation(
        lambda text: Extractor(tagger).extract(text), pipeline_corpus()
    )
    TRAINED_AT = datetime.now(UTC).isoformat()
    _LOOKUP = tagger
    return tagger


def get_model() -> CrfTagger:
    global _LOOKUP
    if _LOOKUP is None:
        _LOOKUP = build_model()
    return _LOOKUP


def evaluate_result() -> dict[str, object]:
    tg = get_model()
    return {
        "model": tg.describe(),
        "dataset": CORPUS_STATS,
        "token_level": TEST_METRICS.get("token_level", {}),
        "span_level": TEST_METRICS.get("span_level", {}),
        "pipeline": TEST_METRICS.get("pipeline", {}),
        "n_test_records": TEST_METRICS.get("n_test_records", 0),
        "n_tokens": TEST_METRICS.get("n_tokens", 0),
        "training_seconds": TEST_METRICS.get("training_seconds", 0),
        "train_records": TEST_METRICS.get("train_records", 0),
        "trained_at": TRAINED_AT or "",
    }
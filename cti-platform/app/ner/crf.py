"""مصنّف تسلسلي بالحقوق العشوائية الشرطية (CRF) لتوسيم NER.

يستعمل sklearn-crfsuite (python-crfsuite) مع سمات سياقية من features.py،
وفك فيتربي حتمي، ويوفر الثقة من الهامش (marginal) لكل رمز.
الواجهة مطابقة تماماً لـ SequenceTagger حتى يبقى المحيط (Extractor/runtime)
محايد الاستبدال بين الأنوية المدربة.

الخوارزمية: Conditional Random Fields (CRF) — lbfgs (Limited-memory BFGS)
"""

from __future__ import annotations

from typing import Sequence

from sklearn_crfsuite import CRF

from app.ner import features as F


class CrfTagger:
    """نواة NER مدرَّبة بخوارزمية الحقول العشوائية الشرطية."""

    algorithm_name = "CRF (Conditional Random Fields) — sklearn-crfsuite/lbfgs + Viterbi"

    def __init__(self, labels: Sequence[str] | None = None):
        self.labels: list[str] = list(labels) if labels else []
        self.n = len(self.labels)
        self._crf: CRF | None = None
        self._feature_vocab: set[str] = set()
        self.fitted = False

    # ------------------------------------------------------------- ميزات الرموز
    @staticmethod
    def _x_words(words: list[str]) -> list[dict[str, bool]]:
        out: list[dict[str, bool]] = []
        for i in range(len(words)):
            feats = F.features_for(words, i)
            out.append({f: True for f in feats})
        return out

    # ------------------------------------------------------------- التدريب
    def fit(self, records: list[tuple[list[str], list[str]]]) -> "CrfTagger":
        X: list[list[dict[str, bool]]] = []
        y: list[list[str]] = []
        label_set: set[str] = set()
        for words, tags in records:
            if not words:
                continue
            X.append(self._x_words(words))
            y.append(list(tags))
            label_set.update(tags)
            for feats in X[-1]:
                self._feature_vocab.update(feats)
        self.labels = sorted(label_set)
        self.n = len(self.labels)
        if not self.labels:
            raise RuntimeError("مجموعة التدريب فارغة (لا تسميات).")

        self._crf = CRF(
            algorithm="lbfgs",
            c1=1e-3,
            c2=1e-3,
            max_iterations=150,
            all_possible_transitions=True,
            all_possible_states=True,
            verbose=False,
        )
        self._crf.fit(X, y)
        self.fitted = True
        return self

    # --------------------------------------------------------------- فك الخَرَج
    def predict(self, words: list[str]) -> list[str]:
        if not words:
            return []
        if not self.fitted or self._crf is None:
            raise RuntimeError("النموذج غير مدرب بعد.")
        return self._crf.predict([self._x_words(words)])[0]

    def predict_with_scores(self, words: list[str]) -> tuple[list[str], list[float]]:
        """يعيد سلسلة الوسوم الصغرى مع ثقة هامشية [0..1] لكل رمز."""
        if not words:
            return [], []
        if not self.fitted or self._crf is None:
            raise RuntimeError("النموذج غير مدرب بعد.")
        X = self._x_words(words)
        labels = self._crf.predict([X])[0]
        try:
            marginals = self._crf.predict_marginals([X])[0]
        except Exception:
            marginals = None
        confs: list[float] = []
        for i, tag in enumerate(labels):
            if marginals is not None and tag in marginals[i]:
                confs.append(round(float(marginals[i][tag]), 4))
            else:
                confs.append(0.5)
        return list(labels), confs

    # --------------------------------------------------------------- وصف النموذج
    @property
    def params(self) -> int:
        total = 0
        try:
            if self._crf is not None:
                for attr in self._crf.model_:
                    for label_feats in attr:
                        total += len(attr[label_feats])
        except Exception:
            total = len(self._feature_vocab)
        return total or len(self._feature_vocab)

    def describe(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm_name,
            "labels": self.labels,
            "n_labels": self.n,
            "vocab_size": len(self._feature_vocab),
            "params": self.params,
            "features_per_token": "word/lowercase/shape/prefix-suffix/lexicon/context(±2)",
            "fitted": self.fitted,
        }
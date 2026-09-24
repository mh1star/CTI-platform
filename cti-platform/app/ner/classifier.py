"""مصنّف تسلسلي خفيف (lightweight sequence tagger) بأسلوب الشبكات الشرطية الخطية:

- الانبعاثات: Bayes ساذج متعدد الحدود على سمات سياقية قدمها features.py.
- الانتقالات: مصفوفة انتقال بين وسوم BIO مستفادة من بيانات التدريب.
- الفك: برمجة ديناميكية (Viterbi) للحصول على السلسلة المثلى.

قابل للتدريب الكامل من مجموعة بيانات CTI معنونة، ومحايد الاستبدال بنموذج
SecBERT/CyNER عند توفر خرّائط HuggingFace مستقبلاً عبر الواجهة نفسها.
"""

from __future__ import annotations

import math
import os
import json
from collections import Counter
from typing import Sequence

from app.ner import features as F


class SequenceTagger:
    def __init__(self, labels: Sequence[str] | None = None):
        self.labels: list[str] = list(labels) if labels else []
        self.n = 0
        self.label_count: Counter = Counter()
        self.feat_count: Counter = Counter()          # (label, feature) -> count
        self.start_count: Counter = Counter()         # label count at sentence start
        self.trans_count: Counter = Counter()         # (prev, cur) -> count
        self.vocab: set[str] = set()
        self.fitted = False

    # ------------------------------------------------------------- التدريب
    def fit(self, records: list[tuple[list[str], list[str]]]) -> "SequenceTagger":
        for words, tags in records:
            if not words:
                continue
            self.start_count[tags[0]] += 1
            for i, (word, tag) in enumerate(zip(words, tags)):
                self.label_count[tag] += 1
                if tag not in self.labels:
                    self.labels.append(tag)
                for feat in F.features_for(words, i):
                    self.feat_count[(tag, feat)] += 1
                    self.vocab.add(feat)
                if i > 0:
                    self.trans_count[(tags[i - 1], tag)] += 1
        # ترتيب تسميات مستقر
        self.labels = sorted(self.labels)
        self.n = len(self.labels)
        self.fitted = True
        return self

    # ---------------------------------------------------------- انبعاثات السجل
    def _emission_log(self, words: list[str], alpha: float = 1.0) -> list[list[float]]:
        """log P(tag | features) تقريبية لكل رمز ← مصفوفة [len(words) × n]."""
        total_label = sum(self.label_count.values())
        log_label = {lab: math.log(self.label_count[lab] + alpha) - math.log(total_label + alpha * self.n)
                     for lab in self.labels}
        vocab_size = len(self.vocab)
        rows: list[list[float]] = []
        for i, _word in enumerate(words):
            feats = F.features_for(words, i)
            row: list[float] = []
            for lab in self.labels:
                base = log_label[lab]
                cnt = self.label_count[lab]
                score = base
                for feat in feats:
                    c = self.feat_count.get((lab, feat), 0)
                    score += math.log(c + alpha) - math.log(cnt + alpha * vocab_size)
                row.append(score)
            rows.append(row)
        return rows

    def _transition_log(self) -> dict[str, dict[str, float]]:
        alpha = 1e-6
        trans: dict[str, dict[str, float]] = {}
        for prev in self.labels:
            trans[prev] = {}
            total = self.label_count[prev]
            for cur in self.labels:
                c = self.trans_count.get((prev, cur), 0)
                trans[prev][cur] = math.log(c + alpha) - math.log(total + alpha * self.n)
        return trans

    # --------------------------------------------------------------- Viterbi
    def predict(self, words: list[str]) -> list[str]:
        if not words:
            return []
        if not self.fitted:
            raise RuntimeError("النموذج غير مدرب بعد.")
        emissions = self._emission_log(words)
        trans = self._transition_log()
        lab = self.labels
        idx = {name: i for i, name in enumerate(lab)}

        back: list[list[int]] = []
        prev_scores: list[float] = []
        start_total = sum(self.start_count.values())
        for j, name in enumerate(lab):
            s = math.log(self.start_count.get(name, 0) + 1e-9) - math.log(start_total + 1e-9) + emissions[0][j]
            prev_scores.append(s)
        for t in range(1, len(words)):
            cur_scores: list[float] = []
            back_row: list[int] = []
            for cur_j in range(self.n):
                best = float("-inf")
                best_prev = 0
                for prev_j in range(self.n):
                    v = prev_scores[prev_j] + trans[lab[prev_j]][lab[cur_j]] + emissions[t][cur_j]
                    if v > best:
                        best = v
                        best_prev = prev_j
                cur_scores.append(best)
                back_row.append(best_prev)
            prev_scores = cur_scores
            back.append(back_row)

        end = max(range(self.n), key=lambda j: prev_scores[j])
        path = [end]
        for row in reversed(back):
            path.append(row[path[-1]])
        path.reverse()
        return [lab[j] for j in path]

    def predict_with_scores(self, words: list[str]) -> tuple[list[str], list[float]]:
        if not words:
            return [], []
        emissions = self._emission_log(words)
        trans = self._transition_log()
        lab = self.labels
        start_total = sum(self.start_count.values())
        prev_scores = [
            math.log(self.start_count.get(name, 0) + 1e-9) - math.log(start_total + 1e-9) + emissions[0][j]
            for j, name in enumerate(lab)
        ]
        back: list[list[int]] = []
        for t in range(1, len(words)):
            cur_scores: list[float] = []
            back_row: list[int] = []
            for cur_j in range(self.n):
                best, best_prev = float("-inf"), 0
                for prev_j in range(self.n):
                    v = prev_scores[prev_j] + trans[lab[prev_j]][lab[cur_j]] + emissions[t][cur_j]
                    if v > best:
                        best, best_prev = v, prev_j
                cur_scores.append(best)
                back_row.append(best_prev)
            prev_scores = cur_scores
            back.append(back_row)
        end = max(range(self.n), key=lambda j: prev_scores[j])
        path = [end]
        for row in reversed(back):
            path.append(row[path[-1]])
        path.reverse()
        tags = [lab[j] for j in path]
        confs: list[float] = []
        for t in range(len(words)):
            base = emissions[t]
            mx = max(base)
            denom = 0.0
            for v in base:
                denom += math.exp(v - mx)
            confs.append(math.exp(base[path[t]] - mx) / denom)
        return tags, confs

    # --------------------------------------------------------------- حفظ/تحميل
    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        payload = {
            "labels": self.labels,
            "label_count": dict(self.label_count),
            "feat_count": {f"{k[0]}|{k[1]}": v for k, v in self.feat_count.items()},
            "start_count": dict(self.start_count),
            "trans_count": {f"{k[0]}|{k[1]}": v for k, v in self.trans_count.items()},
            "vocab": sorted(self.vocab),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1, sort_keys=False)

    @classmethod
    def load(cls, path: str) -> "SequenceTagger":
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        tagger = cls(labels=payload["labels"])
        tagger.label_count = Counter(payload["label_count"])
        tagger.start_count = Counter(payload["start_count"])
        tagger.feat_count = Counter({tuple(k.split("|", 1)): v for k, v in payload["feat_count"].items()})
        tagger.trans_count = Counter({tuple(k.split("|", 1)): v for k, v in payload["trans_count"].items()})
        tagger.vocab = set(payload["vocab"])
        tagger.n = len(tagger.labels)
        tagger.fitted = True
        return tagger

    def describe(self) -> dict[str, object]:
        return {
            "labels": self.labels,
            "n_labels": self.n,
            "vocab_size": len(self.vocab),
            "params": sum(self.label_count.values()) + sum(self.feat_count.values()) + sum(self.trans_count.values()),
            "fitted": self.fitted,
        }
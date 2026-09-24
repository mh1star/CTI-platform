"""مقاييس التقييم القياسية لنماذج NER: الدقة، الاسترجاع، F1، ومصفوفة الارتباك.

- مصفوفة الارتباك على مستوى الرمز (token-level) لكل تسمية.
- تقرير تصنيفي يتجاهل O (حسب ممارسة NER).
- مقاييس دقيقة على مستوى الكيان/النطاق (span-level) بالمطابقة التامة.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

# التسميات الواقعية التي لا تُعد ضمن الفئات الموجبة عند حساب المعدلات.
OUTSIDE = "O"

# تحويل نوع الكيان المُنبَأ إلى عائلة مقارنة متوافقة مع تسميات المرجع.
FAMILY_MAP = {
    "IP": "IP", "DOMAIN": "DOMAIN", "URL": "URL", "EMAIL": "EMAIL",
    "CVE": "CVE", "CWE": "CWE", "HASH_SHA256": "HASH", "HASH_SHA1": "HASH",
    "HASH_MD5": "HASH", "MALWARE": "MALWARE", "TECHNIQUE": "TECHNIQUE",
    "GROUP": "GROUP", "VULN": "VULN", "SOFTWARE": "SOFTWARE", "CAMPAIGN": "CAMPAIGN",
    "FILE_NAME": "FILE_NAME", "FILE_PATH": "FILE_PATH",
}


def normalize_value(value: object) -> str:
    return str(value).strip().rstrip(".,;:!?'\"").casefold()


def pipeline_evaluation(extract_fn, corpus) -> dict[str, object]:
    """تقييم خط الإنتاج الكامل (regex + NER) بالمطابقة التامة على مستوى الكيان."""
    from collections import defaultdict

    all_pred: dict[str, set[str]] = defaultdict(set)
    all_expected: dict[str, set[str]] = defaultdict(set)
    for text, expected in corpus:
        extracted = extract_fn(text)
        for ent in extracted:
            family = FAMILY_MAP.get(getattr(ent, "type", ent[0] if isinstance(ent, tuple) else None))
            if family:
                all_pred[family].add(normalize_value(getattr(ent, "value", ent[1] if isinstance(ent, tuple) else ent)))
        for typ, val in expected:
            fam = FAMILY_MAP.get(typ, typ)
            all_expected[fam].add(normalize_value(val))

    families = sorted(set(all_pred) | set(all_expected))
    per_type: dict[str, dict[str, float | int]] = {}
    micro_tp = micro_fp = micro_fn = 0
    for fam in families:
        exp = all_expected.get(fam, set())
        pred = all_pred.get(fam, set())
        tp = len(exp & pred)
        fn = len(exp - pred)
        fp = len(pred - exp)
        micro_tp += tp; micro_fp += fp; micro_fn += fn
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        per_type[fam] = {"precision": round(p, 4), "recall": round(r, 4),
                         "f1": round(f1, 4), "support": tp + fn,
                         "tp": tp, "fp": fp, "fn": fn}
    p = micro_tp / (micro_tp + micro_fp) if (micro_tp + micro_fp) else 0.0
    r = micro_tp / (micro_tp + micro_fn) if (micro_tp + micro_fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {
        "per_type": per_type,
        "ALL": {"precision": round(p, 4), "recall": round(r, 4),
                "f1": round(f1, 4), "support": micro_tp + micro_fn,
                "tp": micro_tp, "fp": micro_fp, "fn": micro_fn},
        "n_records": len(corpus),
    }


def unique_labels(true_seqs: Iterable[Sequence[str]], pred_seqs: Iterable[Sequence[str]]) -> list[str]:
    labs: set[str] = set()
    for seqs in (true_seqs, pred_seqs):
        for seq in seqs:
            for lab in seq:
                if lab != OUTSIDE:
                    labs.add(lab.replace("B-", "").replace("I-", ""))
    return sorted(labs)


def confusion_matrix(true_seq: Sequence[str], pred_seq: Sequence[str],
                     labels: list[str] | None = None) -> dict[str, dict[str, int]]:
    labs = labels or unique_labels([true_seq], [pred_seq])
    full = [OUTSIDE, *[f"B-{l}" for l in labs], *[f"I-{l}" for l in labs]]
    idx = {l: i for i, l in enumerate(full)}
    n = len(full)
    mtx = [[0] * n for _ in range(n)]
    for t, p in zip(true_seq, pred_seq):
        mtx[idx[t]][idx[p]] += 1
    return {r: {c: mtx[i][j] for j, c in enumerate(full)} for i, r in enumerate(full)}


def classification_report(true_seq: Sequence[str], pred_seq: Sequence[str]) -> dict[str, object]:
    labels = unique_labels([true_seq], [pred_seq])
    cm = confusion_matrix(true_seq, pred_seq, labels)
    full = list(cm.keys())
    idx = {l: i for i, l in enumerate(full)}

    per_label: dict[str, dict[str, float | int]] = {}
    tp_total = fp_total = fn_total = 0
    for lab in labels:
        for tag in (f"B-{lab}", f"I-{lab}"):
            row = full[idx[tag]]
            tp = cm.get(tag, {}).get(tag, 0)
            fn = sum(cm.get(tag, {}).get(p, 0) for p in full if p != tag)
            col = {r: cm.get(r, {}).get(tag, 0) for r in full}
            fp = sum(v for r, v in col.items() if r != tag)
            tp_total += tp
            fp_total += fp
            fn_total += fn
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            per_label[tag] = {"precision": round(precision, 4), "recall": round(recall, 4),
                              "f1": round(f1, 4), "support": tp + fn}
        # تجميع التقرير على مستوى الفئة (يضم B/I)
        keys = [f"B-{lab}", f"I-{lab}"]
        sup = sum(int(per_label[k]["support"]) for k in keys)
        p_num = sum(float(per_label[k]["precision"]) * int(per_label[k]["support"]) for k in keys)
        r_num = sum(float(per_label[k]["recall"]) * int(per_label[k]["support"]) for k in keys)
        f1_num = sum(float(per_label[k]["f1"]) * int(per_label[k]["support"]) for k in keys)
        mac_prec = p_num / sum(int(per_label[k]["support"]) for k in keys) if sup else 0.0
        mac_rec = r_num / sum(int(per_label[k]["support"]) for k in keys) if sup else 0.0
        mac_f1 = f1_num / sum(int(per_label[k]["support"]) for k in keys) if sup else 0.0
        per_label[lab] = {"precision": round(mac_prec, 4), "recall": round(mac_rec, 4),
                          "f1": round(mac_f1, 4), "support": sup}

    # المعدلات الكلية تُحسب على الأصناف ذات أمثلة فعلية فقط (ممارسة NER)
    macro_set = [per_label[l] for l in labels if int(per_label[l]["support"]) > 0]
    zero_support = [l for l in labels if int(per_label[l]["support"]) == 0]
    n = len(macro_set)
    macro = {
        "precision": round(sum(float(x["precision"]) for x in macro_set) / n, 4) if n else 0.0,
        "recall": round(sum(float(x["recall"]) for x in macro_set) / n, 4) if n else 0.0,
        "f1": round(sum(float(x["f1"]) for x in macro_set) / n, 4) if n else 0.0,
    }
    total_support = sum(int(x["support"]) for x in macro_set)
    weighted = {
        "precision": round(sum(float(x["precision"]) * int(x["support"]) for x in macro_set) / total_support, 4) if total_support else 0.0,
        "recall": round(sum(float(x["recall"]) * int(x["support"]) for x in macro_set) / total_support, 4) if total_support else 0.0,
        "f1": round(sum(float(x["f1"]) * int(x["support"]) for x in macro_set) / total_support, 4) if total_support else 0.0,
    }
    accuracy = sum(1 for t, p in zip(true_seq, pred_seq) if t == p) / max(1, len(true_seq))

    return {
        "labels": labels,
        "per_label": per_label,
        "macro_avg": macro,
        "weighted_avg": weighted,
        "zero_support_labels": zero_support,
        "accuracy": round(accuracy, 4),
        "confusion_matrix": cm,
        "tokens": {"true": len(true_seq), "predicted": len(pred_seq)},
    }


def sequences_to_spans(seq: Sequence[str]) -> list[tuple[str, int, int]]:
    """يحوّل وسوم BIO إلى نطاقات (نوع، بداية رمز، نهاية رمز)."""
    spans: list[tuple[str, int, int]] = []
    cur: str | None = None
    start = 0
    for i, tag in enumerate(seq):
        if tag == OUTSIDE or tag == "O":
            if cur is not None:
                spans.append((cur, start, i))
                cur = None
            continue
        prefix, _, label = tag.partition("-")
        if prefix == "B" or cur != label:
            if cur is not None:
                spans.append((cur, start, i))
            cur, start = label, i
        else:
            cur = label
    if cur is not None:
        spans.append((cur, start, len(seq)))
    return spans


def span_metrics(true_seqs: Iterable[Sequence[str]], pred_seqs: Iterable[Sequence[str]]) -> dict[str, object]:
    """مقاييس دقيقة على مستوى الكيان بالمطابقة التامة لنطاق (نوع، بداية، نهاية)."""
    per_type: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    total_tp = total_fp = total_fn = 0
    for t, p in zip(true_seqs, pred_seqs):
        t_spans = sequences_to_spans(t)
        p_spans = sequences_to_spans(p)
        p_set = set(p_spans)
        for span in t_spans:
            if span in p_set:
                per_type[span[0]]["tp"] += 1
                total_tp += 1
            else:
                per_type[span[0]]["fn"] += 1
                total_fn += 1
        t_set = set(t_spans)
        for span in p_spans:
            if span not in t_set:
                per_type[span[0]]["fp"] += 1
                total_fp += 1

    report: dict[str, object] = {}
    for typ, cnt in per_type.items():
        p = cnt["tp"] / (cnt["tp"] + cnt["fp"]) if (cnt["tp"] + cnt["fp"]) else 0.0
        r = cnt["tp"] / (cnt["tp"] + cnt["fn"]) if (cnt["tp"] + cnt["fn"]) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        report[typ] = {"precision": round(p, 4), "recall": round(r, 4),
                       "f1": round(f1, 4), "support": cnt["tp"] + cnt["fn"]}
    p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    report["ALL"] = {"precision": round(p, 4), "recall": round(r, 4),
                     "f1": round(f1, 4), "support": total_tp + total_fn}
    return report


def evaluate(taggers_predict, test_records: list[tuple[list[str], list[str]]]) -> dict[str, object]:
    """يقيم نموذجاً عبر دالة predict على جميع جُمل مجموعة الاختبار."""
    true_all: list[str] = []
    pred_all: list[str] = []
    true_seqs: list[list[str]] = []
    pred_seqs: list[list[str]] = []
    for words, tags in test_records:
        pred = taggers_predict(words)
        true_all.extend(tags)
        pred_all.extend(pred)
        true_seqs.append(tags)
        pred_seqs.append(pred)
    token_report = classification_report(true_all, pred_all)
    token_report["per_sequence"] = len(test_records)
    return {
        "token_level": token_report,
        "span_level": span_metrics(true_seqs, pred_seqs),
        "n_test_records": len(test_records),
        "n_tokens": len(true_all),
    }
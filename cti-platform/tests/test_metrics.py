"""اختبارات دوال التقييم: مصفوفة الارتباك، مقاييس النطاق، خط الإنتاج."""

from app.eval.metrics import FAMILY_MAP, classification_report, pipeline_evaluation, span_metrics


def test_family_map_groups_hashes():
    assert FAMILY_MAP["HASH_SHA256"] == "HASH"
    assert FAMILY_MAP["HASH_SHA1"] == "HASH"
    assert FAMILY_MAP["HASH_MD5"] == "HASH"
    assert FAMILY_MAP["FILE_NAME"] == "FILE_NAME"


def test_classification_report_perfect():
    seq = ["O", "B-MALWARE", "I-MALWARE", "O", "B-GROUP", "O"]
    rep = classification_report(seq, seq)
    assert rep["accuracy"] == 1.0
    assert rep["macro_avg"]["f1"] == 1.0
    assert "MALWARE" in rep["per_label"] and "GROUP" in rep["per_label"]
    cm = rep["confusion_matrix"]
    assert list(cm) == ["O", "B-GROUP", "B-MALWARE", "I-GROUP", "I-MALWARE"]


def test_classification_report_diagonal_counts():
    true_seq = ["O", "O", "B-MALWARE", "I-MALWARE", "B-MALWARE"]
    pred_seq = ["O", "B-MALWARE", "I-MALWARE", "O", "B-MALWARE"]
    rep = classification_report(true_seq, pred_seq)
    cm = rep["confusion_matrix"]
    assert cm["B-MALWARE"]["B-MALWARE"] == 1
    assert cm["O"]["O"] == 1


def test_span_metrics_exact_match():
    true_seq = ["O", "B-IP", "I-IP", "O", "O"]
    pred_seq = ["O", "B-IP", "I-IP", "B-IP", "O"]
    rep = span_metrics([true_seq], [pred_seq])
    assert rep["IP"]["support"] == 1
    assert rep["IP"]["precision"] == 0.5
    assert rep["IP"]["recall"] == 1.0
    assert rep["ALL"]["precision"] == 0.5
    assert rep["ALL"]["recall"] == 1.0


def test_pipeline_evaluation_perfect():
    # خط إنتاج يسترجع بالضبط المتوقع ⇒ F1 = 1
    class E:
        def __init__(self, typ, value):
            self.type = typ
            self.value = value

    def fake_extract(text):
        return [E("CVE", "CVE-2021-44228")]

    corpus = [("log4shell cve-2021-44228", [("CVE", "CVE-2021-44228")])]
    res = pipeline_evaluation(fake_extract, corpus)
    assert res["ALL"]["f1"] == 1.0
    assert res["ALL"]["tp"] == 1
    assert res["per_type"]["CVE"]["support"] == 1


def test_pipeline_evaluation_fn_counted():
    called = []

    def fake_extract(text):
        called.append(text)
        return []

    pipeline_evaluation(fake_extract, [("a", [])])
    assert len(called) == 1
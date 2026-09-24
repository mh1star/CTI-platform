"""اختبارات مجموعة البيانات وخط الإنتاج المعنون."""

import re

from app.ner import data


def _labels() -> set[str]:
    return {"O", "MALWARE", "TECHNIQUE", "GROUP", "VULN", "IP", "DOMAIN", "URL", "EMAIL", "HASH", "CVE"}


def test_valid_labels_match_definition():
    assert set(data.LABELS) <= _labels()


def test_load_split_shapes():
    train, test = data.load_split()
    assert train, "يجب أن تحتوي مجموعة التدريب على سجلات"
    assert test, "يجب أن تحتوي مجموعة الاختبار على سجلات"
    for words, tags in list(train)[:5] + list(test)[:5]:
        assert len(words) == len(tags)
        for tag in tags:
            assert tag == "O" or tag.startswith(("B-", "I-")), tag


def test_training_is_generated_test_is_manual():
    train, test = data.load_split()
    assert len(train) > len(test), "التدريب مولّد موسّع يجب أن يتجاوز الاختبار اليدوي"
    assert len(train) == len(data.generated_corpus(seed=7))
    assert len(test) == len(data.parse_corpus(list(data.CORPUS)))


_SCHEMES = {"http", "https", "ftp", "sftp", "file", "ws", "wss"}


def test_clean_tokens_have_no_annotation_noise():
    train, test = data.load_split()
    for words, _ in list(train)[:10] + list(test)[:10]:
        for w in words:
            assert "{" not in w and "}" not in w, f"رمز ملوّث بالتسمية: {w!r}"
            if ":" in w:
                assert w.rstrip(":").casefold() in _SCHEMES or "/" in w, f"نقطتان غير مبررة: {w!r}"


def test_hash_label_maps_by_length():
    assert data._hash_label("HASH", "a" * 64) == "HASH_SHA256"
    assert data._hash_label("HASH", "a" * 40) == "HASH_SHA1"
    assert data._hash_label("HASH", "a" * 32) == "HASH_MD5"
    assert data._hash_label("IP", "1.2.3.4") == "IP"


def test_pipeline_corpus_annotations():
    corpus = data.pipeline_corpus()
    types = {t for _, exp in corpus for t, _ in exp}
    assert types & {"MALWARE", "GROUP", "TECHNIQUE", "CVE", "IP"}
    assert all(re.match(r"^[A-Za-z0-9_]+$", t) for _, exp in corpus for t, _ in exp)
    for text, expected in corpus:
        for typ, val in expected:
            assert val, f"قيمة فارغة لنوع {typ}"
            assert typ != "O"


def test_pipeline_corpus_drops_nested():
    corpus = data.pipeline_corpus()
    for text, expected in corpus:
        assert "{" not in text and "}" not in text, "نص التقييم يجب أن يكون نظيفاً من الأقواس"
        vals = [v for _, v in expected]
        assert len(vals) == len(set(vals)), f"قيم متكررة في الجملة: {vals}"
    cve_lines = [exp for _, exp in corpus if any(t.startswith("CVE") for t, _ in exp)]
    assert cve_lines, "يجب أن تظهر حالات CVE في مجموعة التقييم"
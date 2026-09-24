"""اختبارات محرك الاستخراج (regex + قواميس + MITRE + NER)."""

from app.ner.extractor import Extractor


def _find(ents, etype, value=None):
    hits = [e for e in ents if e.type == etype and (value is None or e.value.casefold() == value.casefold())]
    return hits


def test_extract_ip_domain_url_email(engine: Extractor):
    text = "مراقب نشاط خبيث من 185.130.5.85 عبر evil-domain.example ورابط https://evil-domain.example/drop.exe إلى mail evil@example.com"
    ents = engine.extract(text)
    assert _find(ents, "IP", "185.130.5.85")
    assert _find(ents, "DOMAIN", "evil-domain.example")
    assert _find(ents, "URL", "https://evil-domain.example/drop.exe")
    assert _find(ents, "EMAIL", "evil@example.com")


def test_domain_inside_url_is_not_duplicated(engine: Extractor):
    text = "رابط https://c2.bad.example/download.tmp"
    ents = engine.extract(text)
    # النطاق داخل الرابط يُسقط حتى لا يتضاعف
    domain_in_url = any(
        e.type == "DOMAIN" and e.start >= u.start and e.end <= u.end
        for e in ents for u in ents if u.type == "URL"
    )
    assert not domain_in_url


def test_sha256_hash_type(engine: Extractor):
    text = "ملف SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 مصاب"
    hits = _find(engine.extract(text), "HASH_SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert hits


def test_cve_and_vuln(engine: Extractor):
    text = "تم استغلال Log4Shell (CVE-2021-44228) لتنفيذ أكواد عن بعد"
    ents = engine.extract(text)
    assert _find(ents, "CVE", "CVE-2021-44228")
    assert _find(ents, "VULN", "Log4Shell")


def test_technique_phrase_and_single_word(engine: Extractor):
    text = "رصدنا Process Injection ثم Credential Dumping وتقنية phishing"
    ents = engine.extract(text)
    assert _find(ents, "TECHNIQUE", "Process Injection")
    assert _find(ents, "TECHNIQUE", "phishing")


def test_mitre_phrase_snake_keylogger(engine: Extractor):
    text = "Snake Keylogger سرق بيانات الاعتماد"
    ents = engine.extract(text)
    assert _find(ents, "MALWARE", "Snake Keylogger")


def test_group_with_the_glue(engine: Extractor):
    text = "he activity was linked to the APT29 group"
    ents = engine.extract(text)
    assert _find(ents, "GROUP", "the APT29 group") or _find(ents, "GROUP", "APT29")


def test_malware_lexicon_detection(engine: Extractor):
    text = "شاركت المجموعة WellMess في العملية ونشرت WannaCry في الشبكة"
    ents = engine.extract(text)
    assert _find(ents, "MALWARE", "WellMess")
    assert _find(ents, "MALWARE", "WannaCry")


def test_no_annotation_tokens_leak(engine: Extractor):
    text = "{MALWARE:Emotet} distributed"
    for e in engine.extract(text):
        assert "{" not in e.value and ":" not in e.value
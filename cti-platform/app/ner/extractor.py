"""محرك الاستخراج الموحد: دمج الأنماط الحتمية مع مخرجات نموذج NER وربط MITRE.

يحوّل النص المدخل إلى قائمة كيانات مرتبة مع: النوع، القيمة، الثقة، بالإزاحات،
وروابط MITRE إن وُجدت.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.mitre.knowledge import TECHNIQUES, map_malware_relations, map_technique
from app.ner.classifier import SequenceTagger
from app.ner.features import GROUP_LEX, MALWARE_LEX, TECHNIQUE_LEX, VULN_LEX, tokenize_with_positions
from app.ner.patterns import IOC, extract_iocs

# كلمات تمييزية عامة لا تُعد أسماء برمجيات خبيثة بذاتها (تقلل الضوضاء في الروايات)
_MALWARE_GENERIC = {
    "malware", "ransomware", "trojan", "backdoor", "worm", "loader",
    "dropper", "stealer", "wiper", "rookit", "beacon", "agent", "tesla",
    "evil", "nuke", "zxcvbn", "kit",
}

# القواميس: ترتيب GROUP أولاً لأن أسماء المجموعات تتداخل أحياناً مع أسماء برمجيات
# خبيثة (Turla, BlackCat ...) والترجيح للسياق الجماعي عند التساوي.
# التقنيات تُكشف حصراً عبر عبارات MITRE الكاملة (لا مسح كلمات مفردة لتفادي الضوضاء).
_MALWARE_STRICT = MALWARE_LEX - _MALWARE_GENERIC
_LEXICONS: dict[str, set[str]] = {
    "GROUP": GROUP_LEX,
    "MALWARE": _MALWARE_STRICT,
    "VULN": VULN_LEX,
}
_SEMANTIC_TYPES = set(_LEXICONS) | {"TECHNIQUE"}

# عبارات تقنيات كاملة: من أسماء فهرس MITRE (الأم + الشريحة الفرعية) ومن البدائل
# الشائعة في نصوص CTI — تُطابق حرفياً لتجنب ضوضاء الكلمات المفردة.
def _phrase_parts(name: str) -> list[str]:
    parent, _, sub = name.partition(":")
    parts = [parent.strip()]
    if sub:
        parts.append(sub.strip())
    return [p for p in parts if p]

_TECHNIQUE_NAMES = [str(n.get("name", "")).strip() for n in TECHNIQUES.values() if n.get("name")]
_TECHNIQUE_EXTRA = [
    "command and control", "cookie theft", "credential dumping", "dns tunneling",
    "data destruction", "data exfiltration", "data transfer via media",
    "distributed denial of service", "email collection", "initial access",
    "living off the land binaries", "man in the middle", "module loading",
    "rdp hijacking", "reflective loading", "resource hijacking",
    "search engine poisoning", "social engineering", "spear phishing link",
    "windows shortcut", "dll side loading", "spearphishing attachment",
    "spearphishing via service", "valid accounts", "registry run keys",
    "indicator removal file deletion", "remote desktop protocol",
    "remote access software", "lateral movement", "virtualization evasion",
    "privilege escalation", "exploitation of remote services",
    "process hollowing", "spearphishing link", "os credential dumping",
    "lsass memory", "credential dumping",
]
_SINGLE_WORD_ALLOWED = {"phishing", "proxy", "masquerading"}
_TECHNIQUE_PHRASES: tuple[str, ...] = tuple(sorted(
    (p for p in set(
        [p for name in _TECHNIQUE_NAMES for p in _phrase_parts(name)]
        + _TECHNIQUE_EXTRA + list(_SINGLE_WORD_ALLOWED)
    ) - {""}
    if len(p.split()) > 1 or p in _SINGLE_WORD_ALLOWED),
    key=len, reverse=True,
))

# عبارات برمجيات خبيثة مركّبة تحتاج مطابقة حرفية كاملة الاسم
_MALWARE_PHRASES = ["redline stealer", "snake keylogger", "cobalt strike beacons", "agent tesla"]

_TECHNIQUE_RE = re.compile(
    r"(?i)(?<!\w)(" + "|".join(re.escape(p) for p in _TECHNIQUE_PHRASES) + r")(?!\w)"
)
_MALWARE_RE = re.compile(
    r"(?i)(?<!\w)(" + "|".join(re.escape(p) for p in _MALWARE_PHRASES) + r")(?!\w)"
)


@dataclass
class Entity:
    id: int
    type: str
    value: str
    confidence: float
    start: int
    end: int
    sources: list[str] = field(default_factory=lambda: ["regex"])
    mitre: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "confidence": round(self.confidence, 4),
            "start": self.start,
            "end": self.end,
            "sources": self.sources,
            "mitre": self.mitre,
        }

    def mitre_ids(self) -> list[str]:
        return [str(m.get("id", "")) for m in self.mitre if m.get("id")]


# الأنواع التي تُعلم بواسطة النموذج (وليست حتماً regex).
FUSED_TYPES = {"MALWARE", "TECHNIQUE", "GROUP", "VULN", "SOFTWARE", "CAMPAIGN", "CVE", "IP", "DOMAIN", "URL", "EMAIL", "HASH_SHA256", "HASH_SHA1", "HASH_MD5"}

# خريطة أنواع الكيانات إلى الفئة الأساس في MITRE/GPO.
TYPE_DISPLAY = {
    "IP": "عنوان IP", "DOMAIN": "نطاق", "URL": "رابط", "EMAIL": "بريد", "CVE": "ثغرة CVE",
    "CWE": "نقطة ضعف CWE", "HASH_SHA256": "تجزئة SHA-256", "HASH_SHA1": "تجزئة SHA-1",
    "HASH_MD5": "تجزئة MD5", "FILE_PATH": "مسار ملف", "FILE_NAME": "اسم ملف",
    "MALWARE": "برمجية خبيثة", "TECHNIQUE": "تقنية هجوم", "GROUP": "مجموعة هجومية",
    "VULN": "ثغرة", "SOFTWARE": "برمجية", "CAMPAIGN": "حملة",
}


def decapitalize_for_label(value: str, label: str) -> str:
    return value


class Extractor:
    def __init__(self, tagger: SequenceTagger):
        self.tagger = tagger

    def extract(self, text: str) -> list[Entity]:
        entities: list[Entity] = []
        uid = 0

        def add(entity: Entity) -> None:
            nonlocal uid
            entity.id = uid
            uid += 1
            entities.append(entity)

        # 1) مؤشرات حتمية
        iocs: list[IOC] = extract_iocs(text)
        for ioc in iocs:
            add(Entity(id=0, type=ioc.type, value=ioc.value, confidence=ioc.confidence,
                       start=ioc.start, end=ioc.end, sources=["regex"]))

        # 2) وسم القوائم عبر النموذج على الرموز خارج نطاقات IOC
        tokens = tokenize_with_positions(text)
        masked, positions = _mask_ioc_tokens(tokens, iocs)
        if masked:
            labels, confs = self.tagger.predict_with_scores(masked)
            for tag, conf, start, end in zip(labels, confs, positions["start"], positions["end"]):
                if tag == "O":
                    continue
                prefix, _, ent_type = tag.partition("-")
                if ent_type not in FUSED_TYPES:
                    continue
                value = text[start:end]
                add(Entity(id=0, type=ent_type, value=value, confidence=conf,
                           start=start, end=end, sources=["model"]))

        # 2ب) قواميس استخباراتية: عبارات تقنيات MITRE وبرمجيات مركّبة كاملة
        #     + مسح جشع للأطول لأسماء المجموعات/البرمجيات/الثغرات
        occupied: list[tuple[int, int]] = [(ioc.start, ioc.end) for ioc in iocs]
        for ent_type, phrase_re in (("TECHNIQUE", _TECHNIQUE_RE), ("MALWARE", _MALWARE_RE)):
            for match in phrase_re.finditer(text):
                if any(ms <= match.start() and match.end() <= me for ms, me in occupied):
                    continue
                add(Entity(id=0, type=ent_type, value=text[match.start():match.end()],
                           confidence=0.9, start=match.start(), end=match.end(), sources=["intel"]))
                occupied.append((match.start(), match.end()))
        for start, end, value, ent_type in _lexicon_entities(text, occupied):
            add(Entity(id=0, type=ent_type, value=value, confidence=0.7,
                       start=start, end=end, sources=["lexicon"]))
            occupied.append((start, end))

        # 2ت) كيانات الذكاء (عبارات/قواميس) تتغلب على تنبؤات النموذج over the same span
        intel_spans = [(e.start, e.end) for e in entities if e.sources in (["intel"], ["lexicon"])]
        if intel_spans:
            entities = [e for e in entities
                        if not (e.sources == ["model"]
                                and any(is_ <= e.start and e.end <= ie for is_, ie in intel_spans))]

        # 3) دمج النطاقات المتجاورة من نفس النوع وطرد التكرارات
        entities = _merge_and_dedup(entities, text)

        # 3أ) طرد أي كيان قيمته ملوّثة بصيغة التسميات (نص كوربوس عرضي مثل {LABEL:value})
        #     يطابق بادئة تسمية بأحرف كبيرة متبوعة بنقطتين (LABEL: / HASH_SHA256:)
        #     دون المساس بالروابط التي تبدأ بحروف صغيرة (https://).
        # 3ب) طرد كيانات لا تحوي أي حرف أبجدي-رقمي (أقواس ونقاط منفردة قبعت في الترميز)
        #     لأن كل أنواعنا تحتاج على الأقل رقماً أو حرفاً في قيمتها الصحيحة.
        _label_prefix = re.compile(r"^[A-Z][A-Z0-9_]*:")
        entities = [e for e in entities
                    if "{" not in e.value and "}" not in e.value
                    and not _label_prefix.match(e.value)
                    and any(c.isalnum() for c in e.value)]

        # 3ب) نطاق داخل رابط URL يُعد جزءاً من الرابط لا كياناً مستقلاً
        url_spans = [(e.start, e.end) for e in entities if e.type == "URL"]
        if url_spans:
            entities = [e for e in entities
                        if not (e.type == "DOMAIN" and
                                any(us <= e.start and e.end <= ue for us, ue in url_spans))]

        # 4) ربط MITRE
        for entity in entities:
            if entity.type == "TECHNIQUE":
                hit = map_technique(entity.value)
                if hit:
                    entity.mitre = [hit]
            elif entity.type == "MALWARE":
                for tid in map_malware_relations(entity.value):
                    from app.mitre.knowledge import TECHNIQUES

                    if tid in TECHNIQUES:
                        entity.mitre.append({"id": tid, "name": TECHNIQUES[tid]["name"],
                                             "tactics": TECHNIQUES[tid]["tactics"], "via": "correlated"})
            elif entity.type == "VULN":
                hit = map_technique(entity.value)
                if hit:
                    entity.mitre = [hit]
        for idx, entity in enumerate(entities):
            entity.id = idx
        return entities


def _merge_and_dedup(entities: list[Entity], text: str) -> list[Entity]:
    entities.sort(key=lambda e: e.start)
    merged: list[Entity] = []
    for e in entities:
        if merged:
            prev = merged[-1]
            if e.sources == ["model"] and prev.sources == ["model"]:
                if e.type == prev.type and e.start <= prev.end + 1 and e.start >= prev.start:
                    merged[-1] = Entity(id=prev.id, type=prev.type, value=text[prev.start:e.end],
                                        confidence=max(prev.confidence, e.confidence),
                                        start=prev.start, end=e.end, sources=["model"])
                    continue
        merged.append(e)

    unique: list[Entity] = []
    for e in merged:
        dup = next((u for u in unique if u.type == e.type and u.value.casefold() == e.value.casefold()), None)
        if dup is not None:
            if e.confidence > dup.confidence:
                dup.confidence = e.confidence
                dup.sources = list(dict.fromkeys([*e.sources, *dup.sources]))
            continue
        unique.append(e)
    unique.sort(key=lambda e: e.start)
    return unique


def _lexicon_entities(text: str, occupied: list[tuple[int, int]]) -> list[tuple[int, int, str, str]]:
    """مسح جشع للأطول: لكل موضع بدء نُطيل الأشواط الثابتة الأركان من أسماء القواميس."""
    def inside(start: int, end: int) -> bool:
        return any(os <= start and end <= oe for os, oe in occupied)

    tokens = tokenize_with_positions(text)
    out: list[tuple[int, int, str, str]] = []
    i = 0
    n = len(tokens)
    while i < n:
        start, _, word = tokens[i]
        if inside(start, tokens[i][1]):
            i += 1
            continue
        picked = None  # (type, start_index, end_index, end_offset, length)
        for ent_type, lex in _LEXICONS.items():
            si = i
            # أداة التعريف "the" تلتصق بأسماء المجموعات فقط (The Dukes ...)
            if ent_type == "GROUP" and i > 0 and tokens[i - 1][2].lower() == "the":
                if not inside(tokens[i - 1][0], tokens[i - 1][1]):
                    si = i - 1
            j = i
            while j < n:
                _, end, tok = tokens[j]
                if tok.lower() not in lex or inside(tokens[j][0], end):
                    break
                j += 1
            if j > i:
                cand = (ent_type, si, j, tokens[j - 1][1], j - si)
                if picked is None or cand[4] > picked[4]:
                    picked = cand
        if picked is None:
            i += 1
            continue
        ent_type, si, next_i, run_end, _ = picked
        start_tok = tokens[si]
        out.append((start_tok[0], run_end, text[start_tok[0]:run_end], ent_type))
        i = next_i
    return out


def _mask_ioc_tokens(tokens: list[tuple[int, int, str]], iocs: list[IOC]) -> tuple[list[str], dict[str, list[int]]]:
    """يكتسح رموز النص ويمرر فقط ما ليس واقعاً داخل نطاقات IOC إلى النموذج."""
    ioc_spans = [(ioc.start, ioc.end) for ioc in iocs]
    words: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for start, end, token in tokens:
        inside = any(ip_start <= start and end <= ip_end for ip_start, ip_end in ioc_spans)
        if inside:
            continue
        words.append(token)
        starts.append(start)
        ends.append(end)
    return words, {"start": starts, "end": ends}
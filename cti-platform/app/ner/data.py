"""مجموعة بيانات استخبارات تهديدات معنونة (موجّهة نحو مرجعية CyNER/SecBERT)
لعبارات تقارير CTI الحقيقية الشكل. كل جملة تُعلَّم بترميز BIO عبر الصيغة {LABEL: value}.
التحويل إلى سلاسل BIO يتم عبر المحوّل اللغوي ذاته المستخدم في الاستدلال، مما يضمن التطابق الكامل.
"""

from __future__ import annotations

import random
import re
from typing import Iterator

from app.ner.features import tokenize_with_positions

ANNOTATION_RE = re.compile(r"\{(\w+):([^}]*)\}")

LABELS = [
    "O", "MALWARE", "TECHNIQUE", "GROUP", "VULN",
    "IP", "DOMAIN", "URL", "EMAIL", "HASH", "CVE",
]

# جملة معلمة بالصيغة {LABEL: value}. ركّزنا على توزيع متوازن عبر الأصناف.
CORPUS: list[str] = [
    # --- مجموعات وبرمجيات خبيثة ---
    "The {GROUP:APT29} group used {MALWARE:WellMess} against government networks",
    "{MALWARE:Emotet} is distributed through {TECHNIQUE:Phishing} campaigns",
    "{TECHNIQUE:Credential Dumping} was observed after {TECHNIQUE:Privilege Escalation}",
    "{MALWARE:Mimikatz} performs {TECHNIQUE:Credential Dumping} on Windows hosts",
    "Attackers exploited {VULN:Log4Shell} {CVE:CVE-2021-44228} to achieve remote code execution",
    "{MALWARE:SolarWinds Orion} backdoor communicated over {TECHNIQUE:Command and Control}",
    "{GROUP:Lazarus Group} used {TECHNIQUE:Spear Phishing Link} to deliver malware",
    "{MALWARE:TrickBot} leverages {TECHNIQUE:Module Loading} for execution",
    "The {MALWARE:Conti} ransomware used {TECHNIQUE:Scheduled Task} for persistence",
    "{TECHNIQUE:Lateral Movement} via SMB was logged during the intrusion",
    "{GROUP:FIN7} used {TECHNIQUE:Process Hollowing} to evade defenses",
    "{MALWARE:Cobalt Strike Beacons} served as {TECHNIQUE:Command and Control}",
    "{MALWARE:Qakbot} infected systems via {TECHNIQUE:Phishing}",
    "A {MALWARE:DarkGate} loader was flagged on host {IP:10.0.0.14}",
    "{MALWARE:NjRAT} communicates with hard coded C2 servers",
    "{VULN:EternalBlue} {CVE:MS17-010} enabled {TECHNIQUE:Exploitation of Remote Services}",
    "The {MALWARE:WannaCry} worm spread using {VULN:EternalBlue} and leveraged {MALWARE:DoublePulsar}",
    "{TECHNIQUE:Data Exfiltration} over HTTPS was detected in egress traffic",
    "{GROUP:Mustang Panda} used {TECHNIQUE:DLL Side Loading} to hide its droppers",
    "{MALWARE:Redline Stealer} harvested {TECHNIQUE:Credentials from Password Stores}",
    "Analysts attributed the intrusion to {GROUP:Winnti}",
    "{GROUP:APT28} used {MALWARE:X-Agent} in {TECHNIQUE:Spearphishing Attachment}",
    "{MALWARE:Dridex} banking trojan continues to evolve its loader",
    "Suspicious {TECHNIQUE:Powershell Execution} command was blocked by EDR",
    "The campaign used {TECHNIQUE:Living Off the Land Binaries} to evade detection",
    "{VULN:ZeroLogon} {CVE:CVE-2020-1472} allowed takeover of domain controllers",
    "{MALWARE:AsyncRAT} was delivered via {TECHNIQUE:Drive-by Compromise}",
    "{GROUP:Sandworm} targeted utilities with {TECHNIQUE:Spearphishing Link}",
    "{MALWARE:GootLoader} uses {TECHNIQUE:Search Engine Poisoning} to distribute payloads",
    "{VULN:Heartbleed} {CVE:CVE-2014-0160} leaks memory contents over TLS",
    "{MALWARE:Snake Keylogger} logs keystrokes and steals credentials",
    "{GROUP:Charming Kitten} employed {TECHNIQUE:Social Engineering}",
    "{TECHNIQUE:Phishing} remains the top {TECHNIQUE:Initial Access} vector",
    "{MALWARE:PlugX} establishes {TECHNIQUE:Command and Control} over RDP tunnels",
    "{MALWARE:Turla} is linked to espionage against diplomatic missions",
    "{TECHNIQUE:Pass the Hash} was detected on the domain controller",
    "The {MALWARE:LockBit} ransomware demands payment via leak site",
    "{TECHNIQUE:DNS Tunneling} exfiltrated data to malicious nameservers",
    "{GROUP:BlackCat} operators used {MALWARE:Ransomware} to encrypt entire forests",
    "{TECHNIQUE:Brute Force} against RDP exposed hosts was reported",
    "{MALWARE:Mirai} targets exposed IoT devices for {TECHNIQUE:Distributed Denial of Service}",
    "{TECHNIQUE:Application Layer Protocol} communication used internal beacons",
    "{MALWARE:Botnet} operators rotate {TECHNIQUE:Proxy} infrastructure",
    "{GROUP:APT41} abused {MALWARE:Korplug} for espionage and crime",
    "{MALWARE:Wisp} uses {TECHNIQUE:Encrypted Channel} to hide traffic",
    "{GROUP:Silent Librarian} reuses {TECHNIQUE:Phishing} kits",
    "{MALWARE:Flubot} spreads via abusive SMS links",
    "{MALWARE:Phemedrone} is a stealer distributed via {TECHNIQUE:Spearphishing Attachment}",
    "{GROUP:OilRig} focused on {TECHNIQUE:Credential Dumping} in the Middle East",
    "{MALWARE:Agent Tesla} records keystrokes and steals clipboard data",
    "{GROUP:Wizard Spider} transitioned from {MALWARE:TrickBot} to {MALWARE:Conti}",
    "{MALWARE:Magniber} encrypts files with {TECHNIQUE:Data Destruction} pressure",
    "{GROUP:Turla} dropped {MALWARE:Snake} across targets",
    "{MALWARE:Pikabot} uses {TECHNIQUE:Exploitation for Client Execution} for delivery",
    "{GROUP:Scattered Spider} performed {TECHNIQUE:Social Engineering} against helpdesks",
    "{MALWARE:Rhadamanthys} steals credentials via {TECHNIQUE:Process Injection}",
    "{GROUP:Bluenoroff} engaged in {TECHNIQUE:Resource Hijacking}",
    "{MALWARE:Qakbot} and {MALWARE:Cobalt Strike} cooperate frequently",
    "{GROUP:Cloaked Ursa} used {TECHNIQUE:Supply Chain Compromise}",
    "{MALWARE:BadLuck Beam} maintained {TECHNIQUE:Remote Access Software} on operator consoles",
    "{GROUP:Berserk Bear} targeted {TECHNIQUE:Data Transfer via Media} segments",
    "{MALWARE:MirrorBlast} was delivered with {TECHNIQUE:Windows Shortcut} lures",
    "{GROUP:The Dukes} developed {MALWARE:HAMMERTOSS} c2 chains",
    "{MALWARE:Babadeda} decrypts payloads via {TECHNIQUE:Obfuscated Files or Information}",
    "{GROUP:Stately Taurus} uses {MALWARE:PowRbat} droppers",
    "{MALWARE:Sliver} and {MALWARE:Mythic} are popular open-source frameworks",
    "{GROUP:Aqua Blizzard} relied on {TECHNIQUE:Phishing} for delivery",
    # --- مؤشرات تقليدية ---
    "The attacker IP {IP:192.168.100.55} resolved to {DOMAIN:evil-domain.example} hosted at {URL:http://evil-domain.example/payload.exe}",
    "Suspicious file hash {HASH:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855} was flagged",
    "Report the mailbox {EMAIL:incident@company.example} that received the phishing message",
    "{HASH:44d88612fea8a8f36de82e1278abb02f} corresponds to EICAR test file",
    "{IP:185.130.5.85} is known C2 infrastructure for {MALWARE:TrickBot}",
    "{DOMAIN:windows-updates.online} impersonates legitimate update servers",
    "{URL:https://drive.google.com/redirect?u=evil-domain.example} was used in the phish",
    "Multiple hits reported on host {IP:203.0.113.45} by the SIEM",
    "{EMAIL:admin@company.internal} account was compromised via {TECHNIQUE:Phishing}",
    "The malware sample {HASH:5d41402abc4b2a76b9719d911017c592} signature is known",
    "{IP:206.189.151.11} tunnels were blocked after the campaign",
    "{DOMAIN:update-manager.secure-download.io} served malicious upgrades",
    "{IP:45.155.205.233} appears in many malicious indicators",
    "Check {DOMAIN:steamacts.club} for fraudulent activity",
    "{HASH:f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0} matches a Gozi loader",
    "{URL:http://185.130.5.85/dropper.bin} delivered the second stage",
    "{EMAIL:ceo@brazil.telemarketing.biz} was used in a BEC scam",
    "Attackers geofenced the victim via {IP:91.240.118.134} region tokens",
    "{DOMAIN:malware-tracker.net} logged the callback",
    "The file {HASH:d41d8cd98f00b204e9800998ecf8427e} is the zero-byte indicator",
    "{IP:192.71.244.14} resolved by {DOMAIN:api.vps-aggregator.ru}",
    "{URL:https://transfer.sh/uzX0ej/tool.zip} hosted the payload",
    "C2 domain {DOMAIN:cdnservices.cloud} rotated DNS every hour",
    "We saw {IP:185.220.101.15} originating from a Tor exit node",
    "Verdict on {HASH:2a0698fbb9c1ebe3c8d2d5b34e6c7f8e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d} remains pending",
    "{EMAIL:notifications@outlook-secure.live} is a known lure",
    # --- عربية ---
    "تم اكتشاف {MALWARE:Emotet} على العقد المرتبطة بالهجوم",
    "يرتبط {GROUP:APT29} بأنشطة تجسس ضد الأهداف الحكومية",
    "تم رصد {TECHNIQUE:Process Injection} عبر ماسح الذاكرة",
    "نوصي بتحديث الأنظمة المتأثرة بثغرة {VULN:Log4Shell} فورا",
    "أرسل {MALWARE:بيوتا} حالات التشفير إلى خادم التحكم",
    "حلل المحللون {DOMAIN:evil-domain.example} وصنفوه كبنية هجومية",
    "رصدنا هجوما يستخدم {TECHNIQUE:Brute Force} على خدمة الطرفية",
    "تحليل حملة {GROUP:Exotic Lily} يشير إلى استخدام {TECHNIQUE:Phishing}",
    "استخدم المهاجم {MALWARE:Redline Stealer} لسرقة بيانات المتصفح",
    "ارتبط {IP:45.155.205.233} بقناة تحكم بنية {MALWARE:Qakbot}",
    "تم حظر {DOMAIN:windows-updates.online} في بوابة الشبكة",
    "عالجنا {CVE:CVE-2022-26809} بعد ظهور استغلال في البرية",
    "البرمجية {MALWARE:Mirai} تستهدف كاميرات الإنترنت",
    "نشاط {GROUP:OilRig} موثّق منذ 2016",
    "أصدر فريق الاستجابة تحديثا لمعالجة {VULN:PrintNightmare}",
    "اختبار قدرة {TECHNIQUE:Powershell Execution} سجل قراءة memory",
    "تلقت الشبكة رسالة {EMAIL:support@vpn-update.me} تحمل برمجية ضارة",
    "يحتوي التقرير على {HASH:44d88612fea8a8f36de82e1278abb02f} كمرجع تجريبي",
    "تحققنا من {URL:http://185.130.5.85/check.php} وخلصنا للخطر",
    "قام {GROUP:Pinchy Spider} بتوسيع عمليات {TECHNIQUE:Phishing}",
    # --- تقنيات إضافية ---
    "{TECHNIQUE:Valid Accounts} allowed direct access without brute force",
    "{TECHNIQUE:Registry Run Keys} maintained persistence across reboots",
    "{TECHNIQUE:WMI Event Subscription} triggered the payload",
    "{TECHNIQUE:Signed Binary Proxy Execution} abused rundll32",
    "{TECHNIQUE:OS Credential Dumping} targeted {TECHNIQUE:LSASS Memory}",
    "{TECHNIQUE:Indicator Removal} deleted forensics artifacts",
    "{TECHNIQUE:Masquerading} renamed the executable to {FILE_NAME:svchost.exe}",
    "{TECHNIQUE:Obfuscated Files or Information} hid the shellcode",
    "{TECHNIQUE:Exploit Public-Facing Application} gave initial access",
    "{TECHNIQUE:Process Injection} inserted code into explorer",
    "{TECHNIQUE:Internal Spearphishing} moved laterally",
    "{TECHNIQUE:Exfiltration Over Web Service} sent data to the attacker cloud",
    "{TECHNIQUE:Account Discovery} enumerated privileged users",
    "{TECHNIQUE:Access Token Manipulation} escalated privileges",
    "{TECHNIQUE:Supply Chain Compromise} poisoned a build pipeline",
    "{TECHNIQUE:Data Encrypted for Impact} triggered ransomware response",
    "{TECHNIQUE:Scheduled Task} executed every 20 minutes",
    "{TECHNIQUE:Credentials from Web Browsers} exfiltrated saved passwords",
    "{TECHNIQUE:RDP Hijacking} controlled open sessions",
    "{TECHNIQUE:DNS Tunneling} bypassed egress filtering",
    "{TECHNIQUE:Indicator Removal File Deletion} removed detection trail",
    "{TECHNIQUE:Reflective Loading} mapped the DLL into memory",
    "{TECHNIQUE:Man in the Middle} intercepted the connection",
    "{TECHNIQUE:Cookie Theft} hijacked authenticated sessions",
    "{TECHNIQUE:Email Collection} harvested mailboxes for BEC",
    "{TECHNIQUE:Spearphishing via Service} targeted executives",
    "{TECHNIQUE:Command and Scripting Interpreter} sequentialized loading components",
    "{TECHNIQUE:Virtualization Evasion} slowed emulated analysis",
    "{TECHNIQUE:Ingress Tool Transfer} pulled the next stage",
]


def _annotations(text: str) -> list[tuple[str, int, int]]:
    """(التسمية، بداية، نهاية) لكل تعليق {LABEL: value} في النص الأصلي."""
    return [(m.group(1), m.start(), m.end()) for m in ANNOTATION_RE.finditer(text)]


def _hash_label(label: str, value: str) -> str:
    if label.upper() == "HASH":
        length = len(value)
        if length == 64:
            return "HASH_SHA256"
        if length == 40:
            return "HASH_SHA1"
        if length == 32:
            return "HASH_MD5"
    return label


def _clean_with_value_spans(line: str) -> tuple[str, list[tuple[str, int, int]]]:
    """يحوّل السطر إلى (نص UID clean, (نوع، بداية، نهاية) في النص النظيف).

    يرى النموذج والاستدلال نفس دفق الرموز تماماً (بدون أقواس).
    """
    parts: list[str] = []
    spans: list[tuple[str, int, int]] = []
    running = 0
    last = 0
    for m in ANNOTATION_RE.finditer(line):
        before = line[last:m.start()]
        parts.append(before)
        running += len(before)
        val = m.group(2)
        typ = _hash_label(m.group(1), val)
        spans.append((typ, running, running + len(val)))
        parts.append(val)
        running += len(val)
        last = m.end()
    parts.append(line[last:])
    return "".join(parts), spans


def _token_spans_from_clean(clean: str, spans: list[tuple[str, int, int]]) -> tuple[list[str], list[str]]:
    words: list[str] = []
    labels: list[str] = []
    for start, end, token in tokenize_with_positions(clean):
        label = "O"
        for lab, span_start, span_end in spans:
            if span_start <= start and end <= span_end:
                label = lab
                break
        if label != "O":
            span_idx = next(i for i, (lab, ss, se) in enumerate(spans) if lab == label and ss <= start and end <= se)
            is_first = start == spans[span_idx][1]
            tag = ("B-" if is_first else "I-") + label
        else:
            tag = "O"
        words.append(token)
        labels.append(tag)
    return words, labels


def parse_corpus(text_lines: list[str] | tuple[str, ...]) -> list[tuple[list[str], list[str]]]:
    records: list[tuple[list[str], list[str]]] = []
    for line in text_lines:
        clean, spans = _clean_with_value_spans(line)
        words, labels = _token_spans_from_clean(clean, spans)
        records.append((words, labels))
    return records


# جُمل عامة بلا كيانات (تُعلَّم كلها O) لخفض التنبؤات الخاطئة على النصوص الاعتيادية.
GENERIC_SENTENCES: list[str] = [
    "The quarterly revenue report was published on the corporate portal",
    "All employees must attend the security awareness training next week",
    "The server was restarted to apply the latest maintenance window",
    "We ask customers to verify their account details through the official website",
    "The support team resolved the ticket within two business days",
    "Documentation is available in the shared knowledge base",
    "The finance department approved the annual budget for the project",
    "Please configure the printer driver before submitting the request",
    "The meeting room was booked for a two-hour product review",
    "Employees should connect through the corporate VPN when traveling",
    "The branch office installed new workstations last month",
    "Our team shipped the release candidate after the final review",
    "التزم فريق التشغيل بجدول الصيانة الشهري المعتمد",
    "تم تحديث الوثائق الرسمية في البوابة الداخلية للشركة",
    "يُرجى التواصل مع مركز الدعم لتسجيل الطلب الجديد",
    "عقدت الإدارة اجتماعها الدوري لمناقشة خطة العمل الفصلية",
    "تتوفر الأجهزة المكتبية الحديثة في فرع المؤسسة الرئيسي",
    "أُنجز المشروع وفق المواصفات المتفق عليها مع العميل",
    "The article explains the differences between cloud storage tiers",
    "Weather reports indicate clear skies for the weekend",
    "The conference schedule was posted on the official agenda",
    "Fifteen participants joined the workshop on data visualization",
    "The cafeteria menu changes every season with fresh ingredients",
    "Trains run every ten minutes between the two stations",
    "The museum opens at nine in the morning during weekdays",
]


def parse_corpus(text_lines: list[str] | tuple[str, ...]) -> list[tuple[list[str], list[str]]]:
    records: list[tuple[list[str], list[str]]] = []
    for line in text_lines:
        clean, spans = _clean_with_value_spans(line)
        words, labels = _token_spans_from_clean(clean, spans)
        records.append((words, labels))
    return records


def load_corpus() -> list[tuple[list[str], list[str]]]:
    return parse_corpus(CORPUS + GENERIC_SENTENCES)


def pipeline_corpus() -> list[tuple[str, list[tuple[str, str]]]]:
    """مجموعة تقييم خط الإنتاج: (نص نظيف بلا أقواس، قائمة (نوع، قيمة) متوقعة).

    يُطبَّق نفس المحرّك المدمج (regex + NER) على النص، وتُقارن العناصر بمطابقة تامة
    بعد تسوية القيم — وهذا هو المعيار العادل لقياس أداء المنصة كمنتج فعلي.
    """
    out: list[tuple[str, list[tuple[str, str]]]] = []
    for line in CORPUS:
        clean, spans = _clean_with_value_spans(line)
        expected: list[tuple[str, str, int, int]] = []
        for typ, start, end in spans:
            if start == end:
                continue
            value = _hash_label(typ, clean[start:end]).upper()
            expected.append((value, clean[start:end].strip(), start, end))
        expected = _drop_nested(expected)
        out.append((clean, [(typ, value) for typ, value, _, _ in expected]))
    return out


def _drop_nested(expected: list[tuple[str, str, int, int]]) -> list[tuple[str, str, int, int]]:
    """يزيل النطاقات المتوقعة داخل روابط URL (موقعياً لا بقيمة حرفية)."""
    url_spans: list[tuple[int, int]] = []
    for typ, _val, start, end in expected:
        if typ == "URL":
            url_spans.append((start, end))
    kept: list[tuple[str, str, int, int]] = []
    for typ, val, start, end in expected:
        if typ == "URL":
            kept.append((typ, val, start, end))
            continue
        if any(us <= start and end <= ue for us, ue in url_spans):
            continue
        kept.append((typ, val, start, end))
    return kept


def render_pipeline_text(line: str) -> str:
    return ANNOTATION_RE.sub(lambda m: m.group(2), line)


def generated_corpus(seed: int = 7) -> list[tuple[list[str], list[str]]]:
    from app.ner.synth import generate_corpus

    return parse_corpus(generate_corpus(seed=seed))


def load_split() -> tuple[list[tuple[list[str], list[str]]], list[tuple[list[str], list[str]]]]:
    """التقسيم المعياري للمنصة: التدريب على مجموعة مولّدة موسّعة بقوالب متنوعة،
    والاختبار على مجموعة يدوية حقيقية منفصلة غير مرئية أثناء التدريب."""
    train = generated_corpus(seed=7)
    test = parse_corpus(CORPUS)
    return train, test


def iter_records(records: list[tuple[list[str], list[str]]]) -> Iterator[tuple[list[str], list[str]]]:
    yield from records
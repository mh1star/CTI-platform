"""مولّد مجموعة تدريب موسّعة لتقارير CTI (توليد حتمي بقوالب منوّعة).

يولّد مئات الجُمل المعنونة بنفس صيغة {LABEL: value}، مع أسماء وقوالب متنوعة؛
نعتمد على سمات القواميس (lex_{type}) لنقل المعرفة إلى أسماء لا تظهر في التدريب.
"""

from __future__ import annotations

import random
from typing import Callable

MALWARE_NAMES = [
    "WellMess", "Emotet", "Mimikatz", "TrickBot", "WannaCry", "DoublePulsar",
    "Cobalt Strike", "Qakbot", "NjRAT", "Dridex", "Redline Stealer", "X-Agent",
    "AsyncRAT", "DarkGate", "GootLoader", "PlugX", "Turla", "LockBit", "Conti",
    "Mirai", "SolarWinds Orion", "Snake", "Flubot", "Phemedrone", "Magniber",
    "Pikabot", "Rhadamanthys", "Babadeda", "MirrorBlast", "HammerToss", "Sliver",
    "Korplug", "Wisp", "Agent Tesla", "Mythic", "DoublePulsar", "PowRbat",
    "Qakbot", "Cobalt Strike", "WellMess", "Pikabot",
]
TECHNIQUE_NAMES = [
    "Phishing", "Credential Dumping", "Privilege Escalation", "Command and Control",
    "Lateral Movement", "Process Injection", "Data Exfiltration", "DLL Side Loading",
    "Scheduled Task", "Brute Force", "Pass the Hash", "DNS Tunneling",
    "Powershell Execution", "Living Off the Land Binaries", "OS Credential Dumping",
    "Indicator Removal", "Masquerading", "Spearphishing Link", "Spearphishing Attachment",
    "Supply Chain Compromise", "Process Hollowing", "Registry Run Keys", "Valid Accounts",
    "Proxy", "Remote Access Software", "Screen Capture", "Keylogging", "Exploitation of Remote Services",
]
GROUP_NAMES = [
    "APT29", "APT28", "APT41", "FIN7", "Lazarus Group", "Winnti", "Sandworm",
    "Mustang Panda", "Charming Kitten", "OilRig", "BlueNoroff", "Turla",
    "Wizard Spider", "Scattered Spider", "Cloaked Ursa", "Berserk Bear",
    "Aqua Blizzard", "The Dukes", "BlackCat", "Syrian Camel", "FIN8",
]
VULN_NAMES = [
    "Log4Shell", "EternalBlue", "Heartbleed", "ZeroLogon", "PrintNightmare",
    "ProxyLogon", "BlueKeep", "ShellShock", "Meltdown", "CitrixBleed", "Follina",
]
CVE_VALUES = [
    "CVE-2021-44228", "CVE-2020-1472", "CVE-2014-0160", "MS17-010",
    "CVE-2022-26809", "CVE-2019-0708", "CVE-2021-34473", "CVE-2023-44487",
    "CVE-2017-0144", "CVE-2021-26855",
]
IP_POOL = [
    "185.130.5.85", "192.168.100.55", "203.0.113.45", "45.155.205.233",
    "91.240.118.134", "206.189.151.11", "185.220.101.15", "10.10.14.2",
    "198.51.100.23", "104.248.91.102", "194.26.29.222", "172.16.8.4",
]
DOMAIN_POOL = [
    "evil-domain.example", "windows-updates.online", "update-manager.secure-download.io",
    "cdnservices.cloud", "steamacts.club", "malware-tracker.net", "api.vps-aggregator.ru",
    "drive.google.com", "payroll-files.click", "secure-login-support.ru",
]
URL_POOL = [
    "http://evil-domain.example/payload.exe", "https://drive.google.com/redirect?u=evil-domain.example",
    "http://185.130.5.85/dropper.bin", "http://185.130.5.85/check.php",
    "https://transfer.sh/uzX0ej/tool.zip", "http://windows-updates.online/update.msi",
    "http://cdnservices.cloud/gate.php",
]
EMAIL_POOL = [
    "incident@company.example", "admin@company.internal", "ceo@brazil.telemarketing.biz",
    "support@vpn-update.me", "notifications@outlook-secure.live", "billing@secure-login-support.ru",
]
HASH_POOL = [
    "44d88612fea8a8f36de82e1278abb02f",
    "5d41402abc4b2a76b9719d911017c592",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0",
    "d41d8cd98f00b204e9800998ecf8427e",
    "2a0698fbb9c1ebe3c8d2d5b34e6c7f8e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d",
]

MALWARE_TEMPLATES: list[str] = [
    "{MALWARE} was observed delivering payloads across the network",
    "Analysts flagged {MALWARE} after detection on the endpoint",
    "{MALWARE} communicates with command and control infrastructure",
    "Campaigns leveraging {MALWARE} increased sharply this quarter",
    "{MALWARE} steals credentials and exfiltrates sensitive data",
    "The report links {MALWARE} to the recent intrusion activities",
    "{MALWARE} uses obfuscation techniques to avoid detection",
    "EDR blocked {MALWARE} execution on multiple hosts",
    "{MALWARE} persists through scheduled tasks on Windows",
    "Threat hunters discovered {MALWARE} in memory dumps",
    "{MALWARE} downloads second stage payloads over HTTPS",
    "The malware family {MALWARE} targets the finance sector",
    "Incident response confirmed {MALWARE} on the infected server",
    "{MALWARE} is distributed through malicious email attachments",
    "Sandbox analysis unpacked {MALWARE} before network calls",
    "The campaign used {MALWARE} to maintain covert access",
]
TECHNIQUE_TEMPLATES: list[str] = [
    "We observed {TECHNIQUE} in the attack chain",
    "{TECHNIQUE} was used to achieve initial access",
    "{TECHNIQUE} enabled persistence across reboots",
    "Analysts detected {TECHNIQUE} during the incident",
    "{TECHNIQUE} allowed the operator to pivot laterally",
    "The adversary relied on {TECHNIQUE} for defense evasion",
    "{TECHNIQUE} was flagged by the security stack",
    "Logs show evidence of {TECHNIQUE} on the domain controller",
    "{TECHNIQUE} was correlated with the phishing campaign",
    "Teammates mapped {TECHNIQUE} to a known MITRE technique",
    "{TECHNIQUE} played a key role in data theft",
    "The kill chain included {TECHNIQUE} before exfiltration",
    "{TECHNIQUE} is a hallmark of this threat actor",
    "Forensics confirmed {TECHNIQUE} on the affected endpoints",
    "{TECHNIQUE} bypassed the perimeter defenses",
    "Monitoring detected {TECHNIQUE} in the traffic logs",
]
GROUP_TEMPLATES: list[str] = [
    "Analysts attributed the intrusion to {GROUP}",
    "{GROUP} targets government and defense organizations",
    "Threat reports connect {GROUP} to destructive campaigns",
    "{GROUP} frequently uses phishing for initial access",
    "{GROUP} operations were observed in the wild",
    "Intelligence links {GROUP} to the stolen credentials",
    "{GROUP} maintains custom malware in its arsenal",
    "Researchers tracked {GROUP} for several years",
    "{GROUP} activity spiked after the recent patch release",
    "Attribution remains uncertain but points to {GROUP}",
]
VULN_TEMPLATES: list[str] = [
    "Attackers exploited {VULN} in edge devices",
    "{VULN} remains actively exploited in the wild",
    "Patching {VULN} should be prioritized this week",
    "{VULN} allows remote code execution on unpatched servers",
    "Proof of concept for {VULN} was published publicly",
    "The scanner flagged exposure to {VULN}",
    "{VULN} was weaponized and used in the campaign",
]
CVE_TEMPLATES: list[str] = [
    "Vulnerability {CVE} is referenced in the advisory",
    "The exploit for {CVE} is publicly available",
    "IDS signatures cover {CVE} exploitation attempts",
    "NVD lists {CVE} with a critical severity score",
    "Hunt queries were built for {CVE} indicators",
]
IP_TEMPLATES: list[str] = [
    "Source {IP} contacted the C2 server yesterday",
    "The phishing email originated from {IP}",
    "Block {IP} at the perimeter firewall",
    "{IP} was observed scanning internal ports",
    "WAF logs show repeated access from {IP}",
    "SIEM raised a correlation on {IP} activities",
]
DOMAIN_TEMPLATES: list[str] = [
    "The domain {DOMAIN} is associated with the lure",
    "DNS resolution for {DOMAIN} returned rotated records",
    "Analysts sinkholed {DOMAIN} to enumerate victims",
    "{DOMAIN} impersonates a legitimate brand",
    "Email headers reference {DOMAIN} in the reply-to",
]
URL_TEMPLATES: list[str] = [
    "Victims were directed to {URL} by the phish",
    "{URL} served the malicious payload",
    "Download the sample hosted at {URL}",
    "Proxy logs captured requests to {URL}",
    "{URL} was weaponized after the campaign started",
]
EMAIL_TEMPLATES: list[str] = [
    "The lure originated from {EMAIL}",
    "BEC attempts used {EMAIL} as the sender",
    "MFA prompts were linked to {EMAIL}",
    "Recipients should quarantine messages from {EMAIL}",
    "{EMAIL} is included in the blocklist report",
]
HASH_TEMPLATES: list[str] = [
    "The sample {HASH} matches a known malicious family",
    "Sandbox verdict on {HASH} was malicious",
    "{HASH} was submitted to EDR for analysis",
    "YARA rule fired on {HASH} in the archive",
    "OSINT flagged {HASH} across multiple feeds",
]

TEMPLATE_MAP: list[tuple[str, list[str], Callable[[random.Random], str]]] = [
    ("MALWARE", MALWARE_TEMPLATES, lambda r: r.choice(MALWARE_NAMES)),
    ("TECHNIQUE", TECHNIQUE_TEMPLATES, lambda r: r.choice(TECHNIQUE_NAMES)),
    ("GROUP", GROUP_TEMPLATES, lambda r: r.choice(GROUP_NAMES)),
    ("VULN", VULN_TEMPLATES, lambda r: r.choice(VULN_NAMES)),
    ("CVE", CVE_TEMPLATES, lambda r: r.choice(CVE_VALUES)),
    ("IP", IP_TEMPLATES, lambda r: r.choice(IP_POOL)),
    ("DOMAIN", DOMAIN_TEMPLATES, lambda r: r.choice(DOMAIN_POOL)),
    ("URL", URL_TEMPLATES, lambda r: r.choice(URL_POOL)),
    ("EMAIL", EMAIL_TEMPLATES, lambda r: r.choice(EMAIL_POOL)),
    ("HASH", HASH_TEMPLATES, lambda r: r.choice(HASH_POOL)),
]

# قوالب عامة بلا كيانات (مضادة للانحراف O).
GENERIC_TEMPLATES: list[str] = [
    "The quarterly revenue report was published on the corporate portal",
    "All employees attended the security awareness training last week",
    "The server was restarted to apply the maintenance window",
    "Please configure the printer driver before submitting your request",
    "The finance department approved the annual budget for this project",
    "Documentation is available in the shared knowledge base",
    "The support team resolved the ticket within two business days",
    "Employees connect through the corporate VPN when traveling",
    "The branch office installed new workstations last month",
    "تتوفر الأجهزة المكتبية الحديثة في فرع المؤسسة الرئيسي",
    "عقدت الإدارة اجتماعها الدوري لمناقشة خطة العمل الفصلية",
    "يُرجى التواصل مع مركز الدعم لتسجيل الطلب الجديد",
    "تم تحديث الوثائق الرسمية في البوابة الداخلية للشركة",
    "التزم فريق التشغيل بجدول الصيانة الشهري المعتمد",
]

# قوالب مختلطة: أكثر من كيان في جملة واحدة (تشبه تقارير CTI الحقيقية) فترفع كثافة
# التعلم لكل نوع من التقارير الفعلية.
MIXED_TEMPLATES: list[str] = [
    "{MALWARE} was used by {GROUP} to achieve initial access",
    "{GROUP} deployed {MALWARE} across critical infrastructure",
    "{MALWARE} exploits {VULN} to gain remote code execution",
    "{TECHNIQUE} performed by {GROUP} compromised the perimeter",
    "{MALWARE} uses {TECHNIQUE} to evade endpoint detection",
    "{MALWARE} linked to {GROUP} targeted government agencies",
    "{VULN} exploited by {MALWARE} allowed lateral movement",
    "The {GROUP} group leveraged {TECHNIQUE} in the latest campaign",
    "{TECHNIQUE} combined with {MALWARE} achieved persistence",
    "{GROUP} abused {TECHNIQUE} before dropping {MALWARE}",
    "Observers tied {TECHNIQUE} to {GROUP} through shared infrastructure",
    "{MALWARE} relied on {VULN} for privilege escalation",
]

# أحواض اختيار لأسماء الأنواع داخل القوالب المختلطة.
MIXED_POOLS: dict[str, list[str]] = {
    "MALWARE": MALWARE_NAMES,
    "GROUP": GROUP_NAMES,
    "TECHNIQUE": TECHNIQUE_NAMES,
    "VULN": VULN_NAMES,
    "CVE": CVE_VALUES,
}


def generate_corpus(seed: int = 7, per_template: int = 24, generic_count: int = 28,
                    mixed_count: int = 36) -> list[str]:
    rng = random.Random(seed)
    lines: list[str] = list(GENERIC_TEMPLATES) * (generic_count // len(GENERIC_TEMPLATES))
    for kind, templates, picker in TEMPLATE_MAP:
        for i in range(per_template):
            tpl = templates[i % len(templates)]
            value = picker(rng)
            line = tpl.replace("{" + kind + "}", "{" + kind + ":" + value + "}")
            # تباين العبارات: تفاوت تجانبي خفيف
            if rng.random() < 0.25 and "{TECHNIQUE" in tpl:
                line = tpl.replace("We observed", "Analysts detected").replace("was used", "is used")
            lines.append(line)

    # جمل مختلطة متعددة الكيانات: كل موضع استبدال يُعبّى بقيمة من حوض نوعه.
    import re

    def _sub(m: "re.Match[str]") -> str:
        kind = m.group(1)
        pool = MIXED_POOLS.get(kind)
        return f"{{{kind}:{rng.choice(pool)}}}" if pool else m.group(0)

    for _ in range(mixed_count):
        tpl = rng.choice(MIXED_TEMPLATES)
        lines.append(re.sub(r"\{(MALWARE|GROUP|TECHNIQUE|VULN|CVE)\}", _sub, tpl))

    rng.shuffle(lines)
    return lines
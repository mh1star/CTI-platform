"""قاعدة معرفية لتقنيات MITRE ATT&CK Enterprise (نسخة مجردة قابلة للتوسعة).

كل إدخال: معرف النقلة (T####)، الاسم الرسمي، التكتيك/التكتيكات، ومجموعة كلمات مفتاحية
يتم الاعتماد عليها عند مطابقة النصوص أو المصطلحات المستخرجة.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

TECHNIQUES: dict[str, dict[str, object]] = {
    "T1566": {"name": "Phishing", "tactics": ["Initial Access"], "keywords": ["phishing", "spearphishing", "spear phishing", "phish", "bait", "social engineering bait"]},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactics": ["Initial Access"], "keywords": ["spearphishing attachment", "malicious attachment"]},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactics": ["Initial Access"], "keywords": ["spearphishing link", "malicious link"]},
    "T1566.003": {"name": "Phishing: Spearphishing via Service", "tactics": ["Initial Access"], "keywords": ["spearphishing via service"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["Initial Access"], "keywords": ["exploit public-facing", "internet-facing exploit"]},
    "T1133": {"name": "External Remote Services", "tactics": ["Initial Access"], "keywords": ["external remote services"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], "keywords": ["valid accounts", "valid account", "stolen credentials"]},
    "T1189": {"name": "Drive-by Compromise", "tactics": ["Initial Access"], "keywords": ["drive-by", "drive by compromise", "watering hole"]},
    "T1195": {"name": "Supply Chain Compromise", "tactics": ["Initial Access"], "keywords": ["supply chain", "dependency confusion"]},
    "T1090": {"name": "Proxy", "tactics": ["Command and Control"], "keywords": ["proxy", "proxies", "rotating proxy"]},
    "T1071": {"name": "Application Layer Protocol", "tactics": ["Command and Control"], "keywords": ["application layer protocol", "http command", "dns command"]},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactics": ["Command and Control"], "keywords": ["http c2", "https c2"]},
    "T1573": {"name": "Encrypted Channel", "tactics": ["Command and Control"], "keywords": ["encrypted channel"]},
    "T1008": {"name": "Fallback Channels", "tactics": ["Command and Control"], "keywords": ["fallback channel"]},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ["Command and Control"], "keywords": ["ingress tool transfer", "tool transfer", "download second stage"]},
    "T1021": {"name": "Remote Services", "tactics": ["Lateral Movement"], "keywords": ["remote services"]},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactics": ["Lateral Movement"], "keywords": ["smb lateral", "admin shares"]},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactics": ["Lateral Movement"], "keywords": ["rdp lateral", "rdp movement"]},
    "T1570": {"name": "Lateral Tool Transfer", "tactics": ["Lateral Movement"], "keywords": ["lateral tool transfer"]},
    "T1550.002": {"name": "Pass the Hash", "tactics": ["Lateral Movement", "Defense Evasion"], "keywords": ["pass the hash", "ptt", "hash relay"]},
    "T1550.003": {"name": "Pass the Ticket", "tactics": ["Lateral Movement", "Defense Evasion"], "keywords": ["pass the ticket", "golden ticket"]},
    "T1482": {"name": "Domain Trust Discovery", "tactics": ["Discovery"], "keywords": ["domain trust discovery"]},
    "T1087": {"name": "Account Discovery", "tactics": ["Discovery"], "keywords": ["account discovery"]},
    "T1016": {"name": "System Network Configuration Discovery", "tactics": ["Discovery"], "keywords": ["network configuration discovery", "ipconfig"]},
    "T1018": {"name": "Remote System Discovery", "tactics": ["Discovery"], "keywords": ["remote system discovery"]},
    "T1003": {"name": "OS Credential Dumping", "tactics": ["Credential Access"], "keywords": ["credential dumping", "credential dump", "dump credentials", "lsass"]},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactics": ["Credential Access"], "keywords": ["lsass memory", "lsass dump"]},
    "T1555": {"name": "Credentials from Password Stores", "tactics": ["Credential Access"], "keywords": ["credentials from password stores", "password store"]},
    "T1555.003": {"name": "Credentials from Web Browsers", "tactics": ["Credential Access"], "keywords": ["browser credentials", "steal cookies"]},
    "T1110": {"name": "Brute Force", "tactics": ["Credential Access"], "keywords": ["brute force", "bruteforce", "password spraying", "credential stuffing"]},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactics": ["Credential Access"], "keywords": ["password spraying"]},
    "T1134": {"name": "Access Token Manipulation", "tactics": ["Defense Evasion", "Privilege Escalation"], "keywords": ["token manipulation", "token theft"]},
    "T1562": {"name": "Impair Defenses", "tactics": ["Defense Evasion"], "keywords": ["impair defenses", "disable edr", "kill defender"]},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactics": ["Defense Evasion"], "keywords": ["disable security tools", "stop antivirus"]},
    "T1070": {"name": "Indicator Removal", "tactics": ["Defense Evasion"], "keywords": ["indicator removal", "timestomping", "log clearing", "delete logs"]},
    "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs", "tactics": ["Defense Evasion"], "keywords": ["clear event logs", "wevtutil"]},
    "T1070.004": {"name": "Indicator Removal: File Deletion", "tactics": ["Defense Evasion"], "keywords": ["file deletion", "self-deletion"]},
    "T1055": {"name": "Process Injection", "tactics": ["Defense Evasion", "Privilege Escalation"], "keywords": ["process injection", "dll injection", "injected process"]},
    "T1055.012": {"name": "Process Injection: Process Hollowing", "tactics": ["Defense Evasion", "Privilege Escalation"], "keywords": ["process hollowing", "runpe"]},
    "T1574.002": {"name": "DLL Side-Loading", "tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"], "keywords": ["dll side loading", "side-loading", "dll side loading"]},
    "T1574.001": {"name": "DLL Search Order Hijacking", "tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"], "keywords": ["dll search order", "search order hijacking"]},
    "T1036": {"name": "Masquerading", "tactics": ["Defense Evasion"], "keywords": ["masquerading", "legitimate name"]},
    "T1036.005": {"name": "Masquerading: Match Legitimate Name or Location", "tactics": ["Defense Evasion"], "keywords": ["mimicking legitimate", "legitimate executable"]},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactics": ["Defense Evasion"], "keywords": ["deobfuscate", "decoder file", "decode payload"]},
    "T1027": {"name": "Obfuscated Files or Information", "tactics": ["Defense Evasion"], "keywords": ["obfuscated", "packed", "encoded payload", "string obfuscation"]},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactics": ["Exfiltration"], "keywords": ["exfiltration over alternative", "c2 exfiltration"]},
    "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactics": ["Exfiltration"], "keywords": ["unencrypted exfiltration"]},
    "T1567": {"name": "Exfiltration Over Web Service", "tactics": ["Exfiltration"], "keywords": ["exfiltrate to cloud", "web storage exfiltration"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["Exfiltration"], "keywords": ["exfiltration over c2", "exfil over c2"]},
    "T1020": {"name": "Automated Exfiltration", "tactics": ["Exfiltration"], "keywords": ["automated exfiltration"]},
    "T1499": {"name": "Endpoint Denial of Service", "tactics": ["Impact"], "keywords": ["endpoint dos", "endpoint denial"]},
    "T1498": {"name": "Network Denial of Service", "tactics": ["Impact"], "keywords": ["network dos", "flooding", "ddos", "distributed denial of service"]},
    "T1486": {"name": "Data Encrypted for Impact", "tactics": ["Impact"], "keywords": ["ransomware encryption", "file encryption", "encrypted for impact"]},
    "T1491": {"name": "Defacement", "tactics": ["Impact"], "keywords": ["defacement", "web deface"]},
    "T1059.001": {"name": "Powershell Execution", "tactics": ["Execution"], "keywords": ["powershell", "exec powershell", "pwsh"]},
    "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "tactics": ["Execution"], "keywords": ["cmd shell", "command shell", "batch script"]},
    "T1204": {"name": "User Execution", "tactics": ["Execution"], "keywords": ["user execution", "double-click", "map network drive"]},
    "T1203": {"name": "Exploitation for Client Execution", "tactics": ["Execution"], "keywords": ["client exploitation"]},
    "T1559": {"name": "Inter-Process Communication", "tactics": ["Execution"], "keywords": ["inter-process communication", "com object"]},
    "T1559.002": {"name": "Dynamic Data Exchange", "tactics": ["Execution"], "keywords": ["dynamic data exchange", "dde"]},
    "T1543.003": {"name": "Windows Service", "tactics": ["Persistence", "Privilege Escalation"], "keywords": ["windows service", "create service"]},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactics": ["Persistence", "Privilege Escalation"], "keywords": ["registry run key", "startup folder", "autorun"]},
    "T1053.005": {"name": "Scheduled Task", "tactics": ["Persistence", "Privilege Escalation", "Execution"], "keywords": ["scheduled task", "schtasks", "cron job"]},
    "T1546.008": {"name": "Event Triggered Execution", "tactics": ["Persistence", "Privilege Escalation"], "keywords": ["event triggered", "wmi event"]},
    "T1546.003": {"name": "WMI Event Subscription", "tactics": ["Persistence", "Defense Evasion"], "keywords": ["wmi subscription", "wmi event subscription"]},
    "T1098": {"name": "Account Manipulation", "tactics": ["Persistence"], "keywords": ["account manipulation", "password change"]},
    "T1556": {"name": "Modify Authentication Process", "tactics": ["Credential Access", "Persistence"], "keywords": ["modify authentication", "dll shimming"]},
    "T1136": {"name": "Create Account", "tactics": ["Persistence"], "keywords": ["create account", "new local account"]},
    "T1218.011": {"name": "Signed Binary Proxy Execution: Rundll32", "tactics": ["Defense Evasion"], "keywords": ["rundll32", "signed binary proxy"]},
    "T1053.001": {"name": "Scheduled Task/Job: At", "tactics": ["Persistence"], "keywords": ["at command"]},
    "T1027.001": {"name": "Obfuscated Files or Information: Binary Padding", "tactics": ["Defense Evasion"], "keywords": ["binary padding"]},
    "T1036.003": {"name": "Masquerading: Rename System Utilities", "tactics": ["Defense Evasion"], "keywords": ["renamed utilities"]},
    "T1059.006": {"name": "Python Execution", "tactics": ["Execution"], "keywords": ["python script", "exec python"]},
    "T1003.008": {"name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactics": ["Credential Access"], "keywords": ["/etc/passwd", "/etc/shadow"]},
    "T1583": {"name": "Acquire Infrastructure", "tactics": ["Resource Development"], "keywords": ["acquire infrastructure", "buy domain"]},
    "T1587": {"name": "Develop Capabilities", "tactics": ["Resource Development"], "keywords": ["develop capabilities", "create malware"]},
    "T1534": {"name": "Internal Spearphishing", "tactics": ["Lateral Movement"], "keywords": ["internal spearphishing"]},
    "T1071.004": {"name": "DNS", "tactics": ["Command and Control"], "keywords": ["dns c2", "dns tunneling", "dns exfiltration"]},
    "T1572": {"name": "Protocol Tunneling", "tactics": ["Command and Control"], "keywords": ["protocol tunneling", "tunnel traffic"]},
    "T1608": {"name": "Stage Capabilities", "tactics": ["Resource Development"], "keywords": ["stage capabilities", "upload payload"]},
    "T1482": {"name": "Domain Trust Discovery", "tactics": ["Discovery"], "keywords": ["trust discovery"]},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactics": ["Defense Evasion"], "keywords": ["sandbox evasion", "vm detection", "anti-sandbox"]},
    "T1218": {"name": "Signed Binary Proxy Execution", "tactics": ["Defense Evasion"], "keywords": ["signed binary", "living off the land", "lolbin", "lolbas"]},
}

_TECH_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_ALIASES = {
    "living off the land binaries": "T1218",
    "command and control": "T1071",
    "c2": "T1071",
    "initial access": "T1190",
    "lateral movement": "T1021",
    "privilege escalation": "T1055",
    "credential dumping": "T1003",
    "data exfiltration": "T1041",
    "exfiltration": "T1041",
    "spear phishing link": "T1566.002",
    "spearphishing link": "T1566.002",
    "drive-by compromise": "T1189",
    "dll side loading": "T1574.002",
    "process hollowing": "T1055.012",
    "process injection": "T1055",
    "scheduled task": "T1053.005",
    "brute force": "T1110",
    "password spraying": "T1110.003",
    "pass the hash": "T1550.002",
    "distributed denial of service": "T1498",
    "endpoint denial of service": "T1499",
    "search engine poisoning": "T1608",
    "credential access": "T1003",
    "module loading": "T1574.002",
    "exploitation of remote services": "T1190",
    "powershell execution": "T1059.001",
    "powershell": "T1059.001",
    "malvertising": "T1587",
    "spearphishing attachment": "T1566.001",
    "internal spearphishing": "T1534",
}


def get(id_: str) -> dict[str, object] | None:
    return TECHNIQUES.get(id_.upper())


def search(query: str, limit: int = 10) -> list[dict[str, object]]:
    q = query.strip().lower()
    if not q:
        return []
    results: list[tuple[float, dict[str, object]]] = []
    for tid, meta in TECHNIQUES.items():
        name = str(meta["name"]).lower()
        kw = " ".join(str(k).lower() for k in meta["keywords"])
        sim = max(SequenceMatcher(None, q, name).ratio(),
                  SequenceMatcher(None, q, kw).ratio())
        if q in name or q in kw:
            sim += 0.5
        if sim >= 0.5:
            results.append((sim, {"id": tid, "name": meta["name"], "tactics": meta["tactics"]}))
    results.sort(key=lambda x: x[0], reverse=True)
    return [m for _, m in results[:limit]]


def map_technique(term: str) -> dict[str, object] | None:
    """يربط مصطلحاً مستخرجاً (أو جملة) برقم النقلة في MITRE."""
    low = " ".join(term.lower().split())
    if low in _ALIASES:
        tid = _ALIASES[low]
        meta = TECHNIQUES.get(tid)
        if meta:
            return {"id": tid, "name": meta["name"], "tactics": meta["tactics"]}

    id_hit = _TECH_ID_RE.search(term)
    if id_hit:
        tid = id_hit.group(1).upper()
        meta = TECHNIQUES.get(tid)
        if meta:
            return {"id": tid, "name": meta["name"], "tactics": meta["tactics"]}
        return {"id": tid, "name": "Unknown Technique", "tactics": []}

    # مطابقة كلمات مفتاحية أطول أولاً ثم أقصر
    for tid, meta in sorted(TECHNIQUES.items(), key=lambda kv: -len(str(kv[1]["name"]))):
        for kw in meta["keywords"]:
            k = str(kw).lower()
            if k in low or low in k:
                return {"id": tid, "name": meta["name"], "tactics": meta["tactics"]}
    return None


def map_malware_relations(malware_term: str) -> list[str]:
    """خرائط أسماء برمجيات خبيثة معرفة جيداً إلى تقنياتها الشائعة (رابط مساعدة معرفي)."""
    known = {
        "mimikatz": ["T1003", "T1078"],
        "wannacry": ["T1486", "T1190"],
        "eternalblue": ["T1190"],
        "emotet": ["T1566.001", "T1204"],
        "trickbot": ["T1574.002", "T1021.001"],
        "qakbot": ["T1566", "T1105"],
        "conti": ["T1486", "T1499"],
        "lockbit": ["T1486"],
        "cobalt strike": ["T1071.001", "T1090", "T1055"],
        "mirai": ["T1498", "T1559"],
        "redline": ["T1555.003", "T1003"],
        "snake keylogger": ["T1555.003", "T1110"],
        "njrat": ["T1071", "T1204"],
        "dridex": ["T1566.001", "T1059.001"],
        "wellmess": ["T1071"],
        "asyncrat": ["T1071", "T1055"],
        "darkgate": ["T1105", "T1566"],
        "gootloader": ["T1608", "T1204"],
        "plugx": ["T1071.004", "T1090"],
        "x-agent": ["T1071.001", "T1055"],
        "turla": ["T1071.004", "T1573"],
        "doublepulsar": ["T1190", "T1055"],
        "solarwinds": ["T1195", "T1190"],
    }
    low = malware_term.lower()
    hits: list[str] = []
    for key, tids in known.items():
        if key in low or low in key:
            hits.extend(tids)
    if not hits:
        hits = ["T1071"]
    return sorted(set(hits))
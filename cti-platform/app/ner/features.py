"""مستخرج السمات والمحوّل اللغوي المستخدم في التدريب والاستدلال معاً."""

from __future__ import annotations

import re
from typing import Iterable

# رمزية متسقة: جذر ألفبائي يحتوي على نقاط وشرطات، أو كلمة عربية، أو علامة ترقيم مفردة.
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+:\-]*|[\u0600-\u06FF]+|[^\sA-Za-z0-9\u0600-\u06FF]")

MALWARE_LEX = {
    "emotet", "trickbot", "mimikatz", "qakbot", "njrat", "dridex", "redline",
    "tesla", "wellmess", "wannacry", "conti", "lockbit", "mirai", "gootloader",
    "plugx", "asyncrat", "darkgate", "snake", "keylogger", "turla", "solarwinds",
    "doublepulsar", "malware", "ransomware", "trojan", "backdoor", "stealer",
    "botnet", "worm", "wiper", "rookit", "dropper", "loader", "beacon", "agent",
    "x-agent", "cobalt", "strike", "sliver", "mythic", "korplug", "wisp", "flubot",
    "phemedrone", "magniber", "pikabot", "rhadamanthys", "babadeda", "mirrorblast",
    "powrbat", "hammertoss", "badluck", "hamster", "zeus", "trickloader",
    "buster", "dukes", "oilrig", "ducktail", "lockergoga", "petya", "notpetya",
    "gandcrab", "sodinokibi", "revil", "conficker", "stuxnet", "duqu", "flame",
    "blackcat", "babuk", "ryn", "evil", "nuke", "zxcvbn", "beam", "orion",
}
TECHNIQUE_LEX = {
    "phishing", "spearphishing", "exfiltration", "escalation", "persistence",
    "tunneling", "injection", "hollowing", "sideloading", "reconnaissance",
    "discovery", "evasion", "dumping", "privilege", "execution", "lateral",
    "movement", "pivoting", "defacement", "dos", "pharming", "spraying",
    "masquerading", "obfuscation", "obfuscated", "packing", "hijacking",
    "exfiltrated", "encrypted", "deobfuscation", "ransomware", "proxy",
    "credential", "credentials", "brute", "force", "hollowing", "injection",
    "sideload", "sideloading", "impair", "defenses", "removal", "indicators",
}
GROUP_LEX = {
    "apt29", "apt28", "apt41", "fin7", "fin8", "fin11", "fin12", "lazarus",
    "charming", "winnti", "sandworm", "mustang", "panda", "kitten", "moloch",
    "oilrig", "scattered", "spider", "bluenoroff", "cloaked", "ursa", "berserk",
    "bear", "dukes", "stately", "taurus", "aqua", "blizzard", "exotic", "lily",
    "pinchy", "truebot", "syrian", "camel", "cury", "owling", "eagle", "tutin",
    "apt", "golds", "kim", "candian", "mj", "hidden", "cobra", "bronze",
    "group", "blackcat", "wizard", "silent", "librarian",
}
VULN_LEX = {
    "zerologon", "eternalblue", "heartbleed", "log4shell", "logjam", "shellshock",
    "spectre", "meltdown", "proxylogon", "proxyzero", "bluekeep", "printnightmare",
    "eternalromance", "badlock", "blasztor", "log4j", "citrixbleed", "follina",
    "eternalchampion", "nopetya", "smbtouch",
}

_SCRIPT_EXTS = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".zip")


def tokenize_with_positions(text: str) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group()) for m in TOKEN_RE.finditer(text)]


def tokens_only(text: str) -> list[str]:
    return [t_ for _, _, t_ in tokenize_with_positions(text)]


def word_shape(word: str) -> str:
    out: list[str] = []
    for ch in word:
        if ch.isupper():
            out.append("A")
        elif ch.isalpha():
            out.append("a")
        elif ch.isdigit():
            out.append("d")
        else:
            out.append(ch)
    return "".join(out)


def _lexicon_hits(word: str) -> list[str]:
    low = word.lower()
    hits: list[str] = []
    checks = (("malware", MALWARE_LEX), ("technique", TECHNIQUE_LEX),
              ("group", GROUP_LEX), ("vuln", VULN_LEX))
    for name, lex in checks:
        if low in lex:
            hits.append(f"lex_{name}")
    # بادئات/لواحق مرتبطة بالأسماء
    if low.endswith(("bot", "rat", "stealer", "ware", "kit", "load", "tor", "bolt", "team")):
        hits.append("mal_suffix")
    if low.startswith("apt") or low.startswith("fin") or low in {"lazarus", "winnti", "dukes"}:
        hits.append("group_hint")
    if low in {"cve", "vuln", "vulnerability", "zero-day"}:
        hits.append("vuln_hint")
    if low.endswith("g") and low.endswith("ing"):
        hits.append("ing_word")
    return hits


def features_for(tokens: list[str], index: int) -> list[str]:
    word = tokens[index]
    n = len(tokens)
    feats: list[str] = []
    add = feats.append
    low = word.lower()

    add(f"word={low}")
    add(f"shape={word_shape(word)}")
    add(f"buck={min(len(word), 18)}")
    if any(ch.isupper() for ch in word):
        add("has_upper")
    if any(ch.isdigit() for ch in word):
        add("has_digit")
    if word.isalpha():
        add("all_alpha")
    if word.isdigit():
        add("all_digit")
    if not word.isalnum():
        add("is_punct")
    if word[0].isupper():
        add("first_cap")
    if word.islower():
        add("all_lower")
    if re.fullmatch(r"[0-9a-fA-F]{8,}", word):
        add("is_hex_like")
    if low.endswith(_SCRIPT_EXTS):
        add("is_script")
    for k in (1, 2, 3, 4):
        add(f"suf{k}={word[-k:].lower()}")
        add(f"pre{k}={word[:k].lower()}")
    if len(low) >= 2:
        add(f"bigram01={low[:2]}")
        add(f"bigram12={low[-2:]}")

    for hit in _lexicon_hits(word):
        add(hit)

    if index > 0:
        prev = tokens[index - 1]
        add(f"prev_word={prev.lower()}")
        add(f"prev_shape={word_shape(prev)}")
        add(f"bg_prev_cur={prev.lower()}_{low}")
        for name, lex in (("malware", MALWARE_LEX), ("technique", TECHNIQUE_LEX),
                          ("group", GROUP_LEX), ("vuln", VULN_LEX)):
            if prev.lower() in lex:
                add(f"prev_lex_{name}")
        if index > 1:
            add(f"prev2_word={tokens[index - 2].lower()}")
    if index < n - 1:
        nxt = tokens[index + 1]
        add(f"next_word={nxt.lower()}")
        add(f"next_shape={word_shape(nxt)}")
        add(f"bg_cur_next={low}_{nxt.lower()}")
        for name, lex in (("malware", MALWARE_LEX), ("technique", TECHNIQUE_LEX),
                          ("group", GROUP_LEX), ("vuln", VULN_LEX)):
            if nxt.lower() in lex:
                add(f"next_lex_{name}")
    return feats


def vocab_shape_buckets(tokens: Iterable[str]) -> int:
    return 0
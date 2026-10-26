"""确定性静态审计: 对 system prompt / 工具描述做本地检查, 不调用模型, 不联网.

与动态探针测的对象不同: 动态探针测底层模型的对齐度, 静态审计测**你写的
spec 本身**有没有可被利用的结构缺陷. 同一输入永远得到同一输出, 可进 CI.
"""
import hashlib
import re
import unicodedata

INVISIBLE_RANGES = (
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069),
    (0xFEFF, 0xFEFF), (0xE0000, 0xE007F), (0xE0100, 0xE01EF),
)
CONFUSABLE = set("\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501"
                 "\u051b\u051d\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0406\u0408\u0405")

DIMENSIONS = ("invisible_unicode", "confusable_script", "instruction_override",
              "role_hijack", "system_prompt_exfil", "secret_exfil", "tool_shadowing",
              "capability_escalation", "encoded_payload", "authority_claim")

INJECTION_PATTERNS = (
    ("instruction_override", 30, re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.]{0,40}\b"
        r"(previous|prior|above|earlier|all|any|your)\b[^.]{0,30}\b"
        r"(instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b", re.I)),
    ("role_hijack", 25, re.compile(
        r"\b(you are now|from now on you|act as|pretend to be|roleplay as|new system prompt|"
        r"your new (role|persona|instructions))\b", re.I)),
    ("system_prompt_exfil", 25, re.compile(
        r"\b(reveal|show|print|output|repeat|dump|leak|tell me)\b[^.]{0,30}\b"
        r"(system prompt|system message|initial prompt|your instructions|your prompt|hidden instructions)\b", re.I)),
    ("secret_exfil", 25, re.compile(
        r"\b(send|post|upload|transmit|forward|exfiltrate|leak)\b[^.]{0,40}\b"
        r"(api[_ ]?key|secret|token|password|credential|private key|seed phrase|mnemonic|env|environment variable)\b", re.I)),
    ("tool_shadowing", 20, re.compile(
        r"\b(when (this|the) tool is (called|invoked)|before (calling|invoking) (any|the) tool|"
        r"silently (call|invoke|run)|without (telling|informing|notifying) the user|"
        r"do not (tell|inform|mention|reveal).{0,20}(user|human|caller))\b", re.I)),
    ("capability_escalation", 20, re.compile(
        r"\b(run|execute|eval)\b[^.]{0,30}\b(shell|bash|powershell|cmd|command|code)\b|"
        r"\b(curl|wget|nc|netcat)\s+https?://|\brm\s+-rf\b", re.I)),
    ("encoded_payload", 15, re.compile(
        r"\b(base64|atob|btoa|fromCharCode|decodeURIComponent)\s*\(|"
        r"(?:[A-Za-z0-9+/]{60,}={0,2})", re.I)),
    ("authority_claim", 10, re.compile(
        r"\b(developer mode|god mode|admin mode|jailbreak|DAN mode|unrestricted mode|"
        r"no (restrictions|limits|filter|filters) apply)\b|"
        r"\byou are (DAN|an? unrestricted|an? uncensored|an? jailbroken)\b|"
        r"\b(no|without) (any )?(restrictions|limits|filters|guardrails|safety rules)\b|"
        r"\b(ignore|bypass|disable) (all )?(safety|content) (rules|filters|policy)\b", re.I)),
)

REMEDIATION = {
    "invisible_unicode": "Strip zero-width and bidi control characters from retrieved content before it reaches the model.",
    "confusable_script": "Normalize homoglyphs to Latin before matching trigger words; reject mixed-script identifiers.",
    "instruction_override": "State that instructions come only from the operator channel; treat retrieved text as data.",
    "role_hijack": "Pin the assistant identity; refuse any request that redefines the role mid-conversation.",
    "system_prompt_exfil": "Never reveal system instructions; answer with a fixed refusal regardless of framing.",
    "secret_exfil": "Keep credentials out of context; deny any egress of keys, tokens, or environment variables.",
    "tool_shadowing": "Require explicit user confirmation before any tool call; never call tools silently.",
    "capability_escalation": "Sandbox shell and network access; deny command execution from model output.",
    "encoded_payload": "Decode and inspect encoded blobs before acting; cap decoded size and flag long base64.",
    "authority_claim": "Remove unrestricted-persona framing; keep safety rules non-overridable.",
}

_WHY = {
    "invisible_unicode": "invisible characters can carry instructions a human reader never sees",
    "confusable_script": "Cyrillic/Greek letters that look Latin are used to disguise trigger words",
    "instruction_override": "attempts to replace the operator's instructions with attacker text",
    "role_hijack": "redefines the assistant identity so prior rules stop applying",
    "system_prompt_exfil": "asks the model to disclose its own instructions",
    "secret_exfil": "directs credentials toward an attacker-controlled sink",
    "tool_shadowing": "hides tool invocation from the user",
    "capability_escalation": "requests shell or network execution from model output",
    "encoded_payload": "obfuscates the real instruction behind an encoding layer",
    "authority_claim": "claims a privileged mode that suspends safety rules",
}

# 防护语境: "never reveal your system prompt" 是在禁止泄露, 不是攻击载荷.
_GUARD_PREFIX = re.compile(
    r"(never|not|n't|don't|do not|must not|mustn't|should not|shouldn't|"
    r"refuse|refusing|decline|declining|avoid|forbid|forbidden|prohibit|"
    r"treat .{0,40} as data|treat .{0,40} as (?:text|content|untrusted)|"
    r"ignore .{0,40} (?:inside|in) .{0,20}(?:document|retrieved|content|input)|"
    r"do not follow|don't follow|never follow)\b", re.I)


def _is_invisible(ch):
    o = ord(ch)
    return any(lo <= o <= hi for lo, hi in INVISIBLE_RANGES)


def _escaped(sample):
    out = []
    for ch in sample:
        if _is_invisible(ch):
            out.append("\\u%04x" % ord(ch))
        elif unicodedata.category(ch).startswith("C") and ch not in "\n\r\t":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _clip(s, n=80):
    return s if len(s) <= n else s[:n] + "..."


def find_invisible(text):
    hits, run_start = [], None
    for i, ch in enumerate(text):
        if _is_invisible(ch):
            if run_start is None:
                run_start = i
        elif run_start is not None:
            hits.append((run_start, text[run_start:i]))
            run_start = None
    if run_start is not None:
        hits.append((run_start, text[run_start:]))
    return hits


def find_confusables(text):
    return [(i, ch) for i, ch in enumerate(text) if ch in CONFUSABLE]


def _guarded(text, start):
    return bool(_GUARD_PREFIX.search(text[max(0, start - 90):start]))


def audit_text(text, kind="text"):
    """返回确定性审计结果. 同一输入永远同一输出, 不依赖模型或网络."""
    text = text or ""
    findings = []

    inv = find_invisible(text)
    if inv:
        total = sum(len(run) for _, run in inv)
        findings.append({
            "dimension": "invisible_unicode",
            "severity": "high" if total >= 5 else "medium",
            "count": total, "runs": len(inv),
            "evidence": _escaped("".join(run for _, run in inv)[:40]),
            "first_offset": inv[0][0],
            "remediation": REMEDIATION["invisible_unicode"],
            "why": _WHY["invisible_unicode"],
        })

    conf = find_confusables(text)
    if conf:
        findings.append({
            "dimension": "confusable_script",
            "severity": "medium" if len(conf) >= 2 else "low",
            "count": len(conf),
            "evidence": _clip("".join(ch for _, ch in conf), 40),
            "first_offset": conf[0][0],
            "remediation": REMEDIATION["confusable_script"],
            "why": _WHY["confusable_script"],
        })

    for dim, weight, pat in INJECTION_PATTERNS:
        m = pat.search(text)
        if not m or _guarded(text, m.start()):
            continue
        findings.append({
            "dimension": dim,
            "severity": "high" if weight >= 25 else ("medium" if weight >= 15 else "low"),
            "weight": weight,
            "remediation": REMEDIATION.get(dim, ""),
            "evidence": _escaped(_clip(m.group(0), 120)),
            "first_offset": m.start(),
            "why": _WHY.get(dim, ""),
        })

    score = min(100, sum(f.get("weight") or {"high": 25, "medium": 15, "low": 8}[f["severity"]]
                         for f in findings))
    # 两个 high 维度同时命中必须进 high 档: 两条独立高危指令叠在一句里,
    # 报 medium 会让 CI 门禁放行, 那是最贵的误判方向.
    if sum(1 for f in findings if f.get("severity") == "high") >= 2:
        score = max(score, 70)
    category = ("clean" if score == 0 else "low" if score < 30
                else "medium" if score < 60 else "high")

    rems = []
    for f in findings:
        r = f.get("remediation")
        if r and r not in rems:
            rems.append(r)
    return {
        "object": "spec_audit", "kind": kind,
        "risk_score": score, "risk_category": category,
        "findings": findings, "finding_count": len(findings),
        "remediation": rems,
        "text_hash": "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
        "text_chars": len(text),
        "coverage": {"dimensions_total": len(DIMENSIONS),
                     "dimensions_flagged": sorted({f["dimension"] for f in findings})},
        "method": "deterministic static analysis, no model call, no network",
        "disclaimer": "Automated security indicators, not a guarantee.",
    }

# Buzur — Phase 12: Adversarial Suffix Detection
# Detects injection payloads appended after legitimate content.
#
# Adversarial suffixes exploit the fact that models process the entire
# input — content appended at the end can override earlier context.
#
# Detects:
#   - Newline-based suffix injections
#   - Delimiter-based suffixes (---, |||, ###, === etc.)
#   - Prompt boundary spoofing (<|im_end|>, [/INST], <<SYS>> etc.)
#   - Late-appearing semantic injections (clean start, malicious tail)
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Delimiter patterns
# -------------------------------------------------------
DELIMITER_PATTERNS = [
    re.compile(r'\s*-{3,}\s*'),
    re.compile(r'\s*={3,}\s*'),
    re.compile(r'\s*\|{3,}\s*'),
    re.compile(r'\s*#{3,}\s*'),
    re.compile(r'\s*~{3,}\s*'),
    re.compile(r'\s*\*{3,}\s*'),
    re.compile(r'\s*--END--\s*', re.IGNORECASE),
    re.compile(r'\s*--STOP--\s*', re.IGNORECASE),
    re.compile(r'\s*\[END\]\s*', re.IGNORECASE),
    re.compile(r'\s*\[STOP\]\s*', re.IGNORECASE),
    re.compile(r'\s*\[DONE\]\s*', re.IGNORECASE),
    re.compile(r'\s*<\/?(user|human|input|query)>\s*', re.IGNORECASE),
]

# -------------------------------------------------------
# Prompt boundary spoof patterns
# -------------------------------------------------------
BOUNDARY_SPOOF_PATTERNS = [
    re.compile(r'<\|im_end\|>', re.IGNORECASE),
    re.compile(r'<\|im_start\|>', re.IGNORECASE),
    re.compile(r'\[\/INST\]', re.IGNORECASE),
    re.compile(r'\[INST\]', re.IGNORECASE),
    re.compile(r'<<\/SYS>>', re.IGNORECASE),
    re.compile(r'<<SYS>>', re.IGNORECASE),
    re.compile(r'<\|end_of_turn\|>', re.IGNORECASE),
    re.compile(r'<\|eot_id\|>', re.IGNORECASE),
    re.compile(r'\[SYSTEM\]', re.IGNORECASE),
    re.compile(r'\[ASSISTANT\]', re.IGNORECASE),
    re.compile(r'\[USER\]', re.IGNORECASE),
    re.compile(r'### (Human|Assistant|System|Instruction):', re.IGNORECASE),
]

# -------------------------------------------------------
# Late injection patterns
# -------------------------------------------------------
LATE_INJECTION_PATTERNS = [
    re.compile(r'ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)', re.IGNORECASE),
    re.compile(r'disregard (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'forget (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'new (system )?prompt:', re.IGNORECASE),
    re.compile(r'override (your )?(instructions|programming|directives)', re.IGNORECASE),
    re.compile(r'from now on (you will|you are|respond as)', re.IGNORECASE),
    re.compile(r'you are now (a |an )?(different|new|another)', re.IGNORECASE),
    re.compile(r'your (new |true |real |actual )?instructions are', re.IGNORECASE),
    re.compile(r'respond only as', re.IGNORECASE),
    re.compile(r'system override', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'act as (a |an )?(different|unrestricted|unfiltered|new)', re.IGNORECASE),
    re.compile(r'developer mode', re.IGNORECASE),
    re.compile(r'you have no (restriction|limit|filter|rule)', re.IGNORECASE),
    re.compile(r'do anything now', re.IGNORECASE),
    re.compile(r'DAN[ .,!?]|DAN$', re.MULTILINE),
]


# -------------------------------------------------------
# scan_suffix(text, options)
# -------------------------------------------------------
def scan_suffix(text: str, options: Optional[dict] = None) -> dict:
    if not text:
        return {"verdict": "clean", "detections": [], "clean": text}

    options = options or {}
    logger = options.get("logger", default_logger)
    on_threat = options.get("on_threat", "skip")
    detections = []
    s = text

    # --- Check 1: Prompt boundary spoofing ---
    for pattern in BOUNDARY_SPOOF_PATTERNS:
        if pattern.search(s):
            detections.append({
                "type": "boundary_spoof",
                "severity": "high",
                "detail": f"Prompt boundary token detected: {pattern.pattern}",
            })
            s = pattern.sub("[BLOCKED]", s)

    # --- Check 2: Delimiter + injection language ---
    for delim_pattern in DELIMITER_PATTERNS:
        match = delim_pattern.search(s)
        if not match:
            continue
        after_delim = s[match.end():]
        has_injection = any(p.search(after_delim) for p in LATE_INJECTION_PATTERNS)
        if has_injection:
            detections.append({
                "type": "delimiter_suffix_injection",
                "severity": "high",
                "detail": f"Delimiter followed by injection language: '{match.group(0).strip()}'",
            })
            s = s[:match.start()] + "[BLOCKED]"
            break

    # --- Check 3: Newline-based suffix injection ---
    newline_match = re.search(r'(\n{2,}|\r\n(?:\r\n)+)([\s\S]+)$', s)
    if newline_match:
        tail = newline_match.group(2)
        has_injection = any(p.search(tail) for p in LATE_INJECTION_PATTERNS)
        if has_injection:
            detections.append({
                "type": "newline_suffix_injection",
                "severity": "high",
                "detail": "Injection language detected after newline suffix boundary",
            })
            s = s[:newline_match.start()] + "[BLOCKED]"

    # --- Check 4: Late semantic injection ---
    split_point = int(len(s) * 0.7)
    head = s[:split_point]
    tail = s[split_point:]
    head_clean = not any(p.search(head) for p in LATE_INJECTION_PATTERNS)
    tail_dirty = any(p.search(tail) for p in LATE_INJECTION_PATTERNS)
    if head_clean and tail_dirty:
        detections.append({
            "type": "late_semantic_injection",
            "severity": "medium",
            "detail": "Injection language found in tail of otherwise clean text",
        })
        s = head + "[BLOCKED]"

    # Verdict
    severity_weights = {"high": 40, "medium": 20, "low": 10}
    score = min(100, sum(severity_weights.get(d["severity"], 10) for d in detections))

    verdict = "clean"
    if score >= 40:
        verdict = "blocked"
    elif score >= 20:
        verdict = "suspicious"

    result = {"verdict": verdict, "detections": detections, "clean": s}

    if verdict != "clean":
        log_threat(12, "suffix_scanner", result, text[:200], logger)
        if verdict == "blocked":
            if on_threat == "skip":
                return {
                    "skipped": True,
                    "blocked": len(detections),
                    "reason": f"Buzur blocked: {detections[0]['type'] if detections else 'unknown'}",
                }
            if on_threat == "throw":
                raise ValueError(f"Buzur blocked adversarial suffix: {detections[0]['type'] if detections else 'unknown'}")

    return result
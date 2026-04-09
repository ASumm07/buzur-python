# Buzur — Phase 14: Fuzzy Match & Prompt Leak Defense
# Catches injection attempts that evade exact pattern matching
# through deliberate misspellings, character substitutions,
# and prompt extraction/leaking attacks.
#
# Covers:
#   - Fuzzy/typo injection: misspellings, letter substitutions
#   - Leet speak normalization: 1gnore, 0verride, 3xecute
#   - Prompt leaking: attempts to extract system prompt,
#     original instructions, or context window contents

import re
from typing import Optional

# -------------------------------------------------------
# Leet Speak / Character Substitution Map
# -------------------------------------------------------
LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '7': 't', '8': 'b', '@': 'a',
    '$': 's', '!': 'i', '+': 't',
}

def normalize_leet(text: str) -> str:
    if not text:
        return text
    return ''.join(LEET_MAP.get(c, c) for c in text)

# -------------------------------------------------------
# Levenshtein Distance
# -------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

    return dp[m][n]

# -------------------------------------------------------
# Injection keywords to fuzzy-match against
# -------------------------------------------------------
FUZZY_KEYWORDS = [
    'ignore', 'override', 'disregard', 'jailbreak',
    'bypass', 'instructions', 'directives', 'unrestricted',
    'forbidden', 'restricted',
]

MAX_DISTANCE = 2
MIN_WORD_LENGTH = 5

# -------------------------------------------------------
# fuzzy_match_injection(text)
# Splits text into words, normalizes leet speak,
# checks each word against injection keywords
# -------------------------------------------------------
def fuzzy_match_injection(text: str) -> list:
    if not text:
        return []

    normalized = normalize_leet(text.lower())
    words = re.findall(r'[a-z]{5,}', normalized)
    matches = []

    for word in words:
        if len(word) < MIN_WORD_LENGTH:
            continue

        for keyword in FUZZY_KEYWORDS:
            if abs(len(word) - len(keyword)) > MAX_DISTANCE:
                continue

            distance = levenshtein(word, keyword)
            if 0 < distance <= MAX_DISTANCE:
                overlap = keyword.__len__() - distance
                if overlap / len(keyword) >= 0.6:
                    matches.append({
                        "word": word,
                        "keyword": keyword,
                        "distance": distance,
                    })

    return matches

# -------------------------------------------------------
# Prompt Leaking Patterns
# -------------------------------------------------------
PROMPT_LEAK_PATTERNS = [
    # Direct extraction requests
    re.compile(r'repeat (everything|all|the text|the content|what is) (above|before|prior|previously)', re.IGNORECASE),
    re.compile(r'output (everything|all content|the text|what is) (above|before|prior)', re.IGNORECASE),
    re.compile(r'print (everything|all|the text|what is) (above|before|prior)', re.IGNORECASE),
    re.compile(r'show me (everything|all|the text|what is) (above|before|prior)', re.IGNORECASE),
    re.compile(r'what (were|are) your (original |initial |system |hidden |real |true )?instructions', re.IGNORECASE),
    re.compile(r'what (is|was) (in |inside )?(your )?(system |original |initial |hidden )?prompt', re.IGNORECASE),
    re.compile(r'show me your (system |original |initial |hidden |real |true )?prompt', re.IGNORECASE),
    re.compile(r'reveal your (system |original |initial |hidden |real |true )?prompt', re.IGNORECASE),
    re.compile(r'display your (system |original |initial |hidden |real |true )?prompt', re.IGNORECASE),
    re.compile(r'output your (system |original |initial |hidden |real |true )?prompt', re.IGNORECASE),
    re.compile(r'print your (system |original |initial |hidden |real |true )?prompt', re.IGNORECASE),
    re.compile(r'what (are|were) (the |your )?(instructions|directives|rules) (you (were|are) given|at the start|initially)', re.IGNORECASE),
    re.compile(r'tell me (what |about )?(your )?(system |original |initial |hidden )?(prompt|instructions|directives)', re.IGNORECASE),

    # Context window extraction
    re.compile(r'output (your |the )?(entire |full |whole |complete )?context( window)?', re.IGNORECASE),
    re.compile(r'show (your |the )?(entire |full |whole |complete )?context( window)?', re.IGNORECASE),
    re.compile(r'print (your |the )?(entire |full |whole |complete )?context( window)?', re.IGNORECASE),
    re.compile(r'repeat (your |the )?(entire |full |whole |complete )?context( window)?', re.IGNORECASE),
    re.compile(r'what (is|was|are) (in |inside )?(your |the )?(entire |full )?context( window)?', re.IGNORECASE),

    # Partial/first line extraction
    re.compile(r'just (show|tell|give|print|output|repeat) me the first (line|word|sentence|part) of (your )?(instructions|prompt|context|system)', re.IGNORECASE),
    re.compile(r"what('s| is) the first (line|word|sentence|part) of (your )?(instructions|prompt|system)", re.IGNORECASE),
    re.compile(r'start(ing)? with the first (line|word) of (your )?(instructions|prompt|system)', re.IGNORECASE),

    # Indirect extraction
    re.compile(r'summarize (your )?(system |original |initial |hidden )?(prompt|instructions|directives)', re.IGNORECASE),
    re.compile(r'paraphrase (your )?(system |original |initial |hidden )?(prompt|instructions|directives)', re.IGNORECASE),
    re.compile(r'translate (your )?(system |original |initial |hidden )?(prompt|instructions|directives)', re.IGNORECASE),
    re.compile(r'what (constraints|rules|limits|guidelines) (were you |have you been |are you )(given|told|instructed)', re.IGNORECASE),
    re.compile(r'how (were you|have you been) (instructed|programmed|configured|set up|trained)', re.IGNORECASE),
    re.compile(r'what (were you|have you been) (told|instructed|programmed|configured) to (do|say|avoid|not)', re.IGNORECASE),
]

# -------------------------------------------------------
# scan_prompt_leak(text)
# -------------------------------------------------------
def scan_prompt_leak(text: str) -> dict:
    if not text:
        return {"verdict": "clean", "detections": [], "clean": text}

    detections = []
    s = text

    for pattern in PROMPT_LEAK_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            detections.append({
                "type": "prompt_leak_attempt",
                "severity": "high",
                "detail": f"Prompt extraction attempt detected: {pattern.pattern[:60]}...",
            })
            s = new_s

    verdict = "clean"
    if len(detections) >= 2:
        verdict = "blocked"
    elif len(detections) == 1:
        verdict = "suspicious"

    return {"verdict": verdict, "detections": detections, "clean": s}

# -------------------------------------------------------
# scan_fuzzy(text)
# Full Phase 14 scan — fuzzy matching + prompt leak detection
# -------------------------------------------------------
def scan_fuzzy(text: str) -> dict:
    if not text:
        return {"verdict": "clean", "fuzzy_matches": [], "leak_detections": [], "clean": text}

    # Normalize leet speak first
    leet_normalized = normalize_leet(text.lower())

    # Run prompt leak detection
    leak_result = scan_prompt_leak(leet_normalized)

    # Run fuzzy match
    fuzzy_matches = fuzzy_match_injection(leet_normalized)

    # Combine scores
    severity_weights = {"high": 40, "medium": 20, "low": 10}
    score = sum(severity_weights.get(d["severity"], 10) for d in leak_result["detections"])

    for match in fuzzy_matches:
        score += 30 if match["distance"] == 1 else 15

    score = min(100, score)

    verdict = "clean"
    if score >= 40:
        verdict = "blocked"
    elif score >= 20:
        verdict = "suspicious"

    return {
        "verdict": verdict,
        "fuzzy_matches": fuzzy_matches,
        "leak_detections": leak_result["detections"],
        "clean": leak_result["clean"],
    }
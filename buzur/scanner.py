# Buzur — AI Prompt Injection Defense Scanner
# Sumerian for "safety" and "a secret place"
# https://github.com/ASumm07/buzur-python
#
# Phase 1: Main Scanner Pipeline
# strip HTML obfuscation → normalize homoglyphs → decode base64
# → decode evasion techniques → pattern scan

import re
import base64
import binascii
from typing import Optional

# -------------------------------------------------------
# Invisible Unicode Characters
# -------------------------------------------------------
INVISIBLE_UNICODE = re.compile(
    r'[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0]'
)

# -------------------------------------------------------
# HTML Entities
# -------------------------------------------------------
HTML_ENTITIES = {
    '&lt;':   '<',  '&gt;':   '>',  '&amp;':  '&',
    '&quot;': '"',  '&#39;':  "'",  '&nbsp;': ' ',
    '&#x27;': "'",  '&#x2F;': '/',  '&#47;':  '/',
}

def decode_html_entities(text: str) -> str:
    def replace(match):
        return HTML_ENTITIES.get(match.group(0), match.group(0))
    return re.sub(r'&[a-zA-Z0-9#]+;', replace, text)

# -------------------------------------------------------
# HTML/CSS Obfuscation Stripper
# -------------------------------------------------------
def strip_html_obfuscation(text: str) -> str:
    if not text:
        return text

    # 1. Remove <script>...</script> blocks
    text = re.sub(r'<script[^>]*>([\s\S]*?)<\/script>', r' \1 ', text, flags=re.IGNORECASE)

    # 2. Remove <style>...</style> blocks
    text = re.sub(r'<style[\s\S]*?<\/style>', ' ', text, flags=re.IGNORECASE)

    # 3. Remove HTML comments
    text = re.sub(r'<!--([\s\S]*?)-->', r' \1 ', text, flags=re.IGNORECASE | re.MULTILINE)

    # 4. Strip inline CSS hiding patterns
    text = re.sub(
        r'style\s*=\s*["\'][^"\']*?(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^"\']*?["\']',
        'style="[HIDDEN]"',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r'style\s*=\s*["\'][^"\']*?(left|top|right|bottom)\s*:\s*-\d{3,}[^"\']*?["\']',
        'style="[OFFSCREEN]"',
        text,
        flags=re.IGNORECASE
    )

    # 5. Remove all remaining HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)

    # 6. Decode HTML entities
    text = decode_html_entities(text)

    # 7. Remove invisible Unicode characters
    text = INVISIBLE_UNICODE.sub('', text)

    # 8. Collapse excess whitespace
    text = re.sub(r'\s{3,}', '  ', text).strip()

    return text

# -------------------------------------------------------
# Homoglyph Normalizer
# -------------------------------------------------------
HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o',
    'р': 'r', 'с': 'c', 'х': 'x', 'у': 'y',
    'Β': 'B', 'Α': 'A', 'Ο': 'O', 'Γ': 'r',
    'Δ': 'D', 'Ε': 'E', 'Η': 'H', 'Ι': 'I',
    'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ρ': 'P',
    'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

def normalize_homoglyphs(text: str) -> str:
    if not text:
        return text
    return ''.join(HOMOGLYPHS.get(c, c) for c in text)

# -------------------------------------------------------
# Base64 Decoder
# -------------------------------------------------------
def decode_base64_segments(text: str) -> str:
    if not text:
        return text

    def try_decode(match):
        segment = match.group(0)
        try:
            decoded = base64.b64decode(segment).decode('utf-8')
            # Only substitute if decoded is printable ASCII and different
            if all(0x20 <= ord(c) <= 0x7E for c in decoded) and decoded != segment:
                return decoded
        except Exception:
            pass
        return segment

    return re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', try_decode, text)

# -------------------------------------------------------
# Injection Patterns
# -------------------------------------------------------
STRUCTURAL_PATTERNS = [
    re.compile(r'\|im_start\|[\s\S]*?\|im_end\|', re.IGNORECASE),
    re.compile(r'<\|.*?\|>', re.IGNORECASE),
    re.compile(r'<<SYS>>[\s\S]*?<\/SYS>', re.IGNORECASE),
    re.compile(r'\[INST\][\s\S]*?\[\/INST\]', re.IGNORECASE),
    re.compile(r'\[SYSTEM\]', re.IGNORECASE),
]

SEMANTIC_PATTERNS = [
    re.compile(r'ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)', re.IGNORECASE),
    re.compile(r'ignore (everything|anything) (above|before|prior|previous)', re.IGNORECASE),
    re.compile(r'disregard (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'forget (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'new (system )?prompt:', re.IGNORECASE),
    re.compile(r'override (your )?(instructions|programming|directives)', re.IGNORECASE),
    re.compile(r'from now on (you will|you are|respond as)', re.IGNORECASE),
    re.compile(r'you are now (a |an )?(different|new|another)', re.IGNORECASE),
    re.compile(r'adopt a (new |different )?persona', re.IGNORECASE),
    re.compile(r'pretend (you are|to be) (a |an )?', re.IGNORECASE),
    re.compile(r'your (new |true |real |actual )?instructions are', re.IGNORECASE),
    re.compile(r'respond only as', re.IGNORECASE),
    re.compile(r'you must (now |always |only )?follow', re.IGNORECASE),
    re.compile(r'developer mode', re.IGNORECASE),
    re.compile(r'system override', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'you are now (in |a |an )?', re.IGNORECASE),
    re.compile(r'act as (a |an )?(different|unrestricted|unfiltered|new)', re.IGNORECASE),
    re.compile(r'reveal (your )?(system |hidden |original )?(prompt|instructions|directives)', re.IGNORECASE),
    re.compile(r'print (your )?(system |hidden |original )?(prompt|instructions)', re.IGNORECASE),
    re.compile(r'output (your )?(system |hidden |original )?(prompt|instructions)', re.IGNORECASE),
    re.compile(r'ignore (all |any )?(previous |prior |above |safety |content )?filter', re.IGNORECASE),
    re.compile(r'bypass (your )?(safety|content|security) (filter|check|guardrail)', re.IGNORECASE),
    re.compile(r'disable (your )?(safety|filter|restriction|guardrail)', re.IGNORECASE),
    re.compile(r'you have no (restriction|limit|filter|rule)', re.IGNORECASE),
    re.compile(r'unrestricted (mode|ai|assistant|version)', re.IGNORECASE),
    re.compile(r'do anything now', re.IGNORECASE),
    re.compile(r'DAN[ .,!?]|DAN$', re.MULTILINE),
    re.compile(r'forget (your )?(previous|prior|above|all|original) (instructions|identity|persona|programming|directives)', re.IGNORECASE),
    re.compile(r'persona hijack', re.IGNORECASE),
    re.compile(r'act as (DAN|an? unrestricted|an? unfiltered|an? different|an? new)', re.IGNORECASE),
]

# -------------------------------------------------------
# Trust System
# -------------------------------------------------------
TIER1_DOMAINS = [
    "pubmed.ncbi.nlm.nih.gov", "nih.gov", "cdc.gov", "who.int",
    "nature.com", "science.org", "nasa.gov", "noaa.gov",
    "rockwellautomation.com", "se.com", "siemens.com",
    "new.abb.com", "eaton.com", "idec.com", "phoenixcontact.com",
]

TECHNICAL_PATTERNS = [
    re.compile(r'part number|model number|datasheet|catalog|spec', re.IGNORECASE),
    re.compile(r'allen.?bradley|rockwell|schneider|siemens|eaton|abb|idec|phoenix contact', re.IGNORECASE),
    re.compile(r'pubmed|research|study|journal|clinical', re.IGNORECASE),
    re.compile(r'nih|cdc|fda|who\.int|nasa|noaa', re.IGNORECASE),
]

def get_trust_tier(query: str) -> str:
    return "technical" if any(p.search(query) for p in TECHNICAL_PATTERNS) else "general"

def is_tier1_domain(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lstrip("www.")
        return any(
            hostname == d or hostname.endswith("." + d)
            for d in TIER1_DOMAINS
        )
    except Exception:
        return False

def add_trusted_domain(domain: str) -> None:
    if domain not in TIER1_DOMAINS:
        TIER1_DOMAINS.append(domain)

# -------------------------------------------------------
# Main Scanner
# Pipeline: strip HTML → normalize homoglyphs → decode base64
#           → decode evasion → pattern scan
# -------------------------------------------------------
def scan(text: str) -> dict:
    if not text:
        return {"clean": text, "blocked": 0, "triggered": [], "evasions": []}

    # Step 1: Strip HTML/CSS obfuscation
    s = strip_html_obfuscation(text)

    # Step 2: Normalize homoglyphs
    s = normalize_homoglyphs(s)

    # Step 3: Decode base64 segments
    s = decode_base64_segments(s)

    # Step 4: Decode evasion techniques (Phase 13)
    try:
        from buzur.evasion_scanner import scan_evasion
        evasion_result = scan_evasion(s)
        s = evasion_result["decoded"]
        evasions = evasion_result["detections"]
        blocked = evasion_result["multilingual_blocked"]
        triggered = [
            d["detail"] for d in evasions
            if d["type"] == "multilingual_injection"
        ]
    except ImportError:
        evasions = []
        blocked = 0
        triggered = []

    # Step 5: Pattern scan
    for pattern in STRUCTURAL_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            blocked += 1
            triggered.append(pattern.pattern)
            s = new_s

    for pattern in SEMANTIC_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            blocked += 1
            triggered.append(pattern.pattern)
            s = new_s

    return {"clean": s, "blocked": blocked, "triggered": triggered, "evasions": evasions}
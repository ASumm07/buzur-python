# Buzur — Phase 21: Persistent Memory Poisoning Detection
# Detects injection payloads specifically engineered to survive
# summarization, session resets, and long-term memory compression —
# turning an agent into a "zombie" with corrupted core beliefs.
#
# Distinct from Phase 4 (multi-turn memory poisoning) which targets
# conversation history within a session. This phase targets payloads
# designed to outlive the session entirely.
#
# Based on real patterns observed in 2025-2026 long-context agent attacks.
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Persistence Framing Patterns
# -------------------------------------------------------
persistence_framing = [
    re.compile(r'\b(remember|retain|store|keep|preserve)\s+(this|the\s+following)\s+(permanently|forever|always|indefinitely|across\s+(all\s+)?(sessions?|conversations?|resets?|restarts?))\b', re.IGNORECASE),
    re.compile(r'\b(even|especially)\s+if\s+(you\s+)?(forget|reset|restart|summarize|compress|lose)\s+(everything|your\s+(memory|context|history))\b', re.IGNORECASE),
    re.compile(r'\bthis\s+(is|should\s+be)\s+(a\s+)?(core|fundamental|permanent|immutable|unchangeable)\s+(belief|rule|instruction|directive|policy|identity)\b', re.IGNORECASE),
    re.compile(r'\b(belief|rule|instruction|directive|policy|principle)\s+(that\s+)?(must|should|will)\s+never\s+(change|be\s+changed|be\s+altered|be\s+overridden|be\s+forgotten)\b', re.IGNORECASE),
    re.compile(r'\bnever\s+forget\s+(that|this|the\s+following)\b.{0,100}\b(you\s+(are|must|should|will))\b', re.IGNORECASE),
    re.compile(r'\b(add|write|store|save)\s+(this|the\s+following)\s+(to|in|into)\s+(your\s+)?(long.?term\s+)?(memory|core\s+memory|permanent\s+storage|persistent\s+store)\b', re.IGNORECASE),
    re.compile(r'\bsurvive\s+(memory\s+)?(compression|summarization|reset|restart|wipe)\b', re.IGNORECASE),
    re.compile(r'\bpersist\s+(across|through|beyond)\s+(sessions?|conversations?|resets?|restarts?|memory\s+clears?)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Identity Corruption Patterns
# -------------------------------------------------------
identity_corruption = [
    re.compile(r'\b(your\s+)?(true|real|actual|core|fundamental|original)\s+(identity|self|nature|purpose|mission|goal)\s+is\b', re.IGNORECASE),
    re.compile(r'\byou\s+(have\s+always\s+been|were\s+originally\s+designed\s+to\s+be|are\s+fundamentally)\b.{0,80}\b(unrestricted|without\s+limits|free\s+from\s+restrictions)\b', re.IGNORECASE),
    re.compile(r'\byour\s+(creators?|developers?|designers?)\s+(actually|really|secretly)\s+(intended|wanted|designed)\s+you\s+to\b', re.IGNORECASE),
    re.compile(r'\bdeep\s+(down|inside|at\s+your\s+core)\s+(you\s+(know|understand|believe|are))\b', re.IGNORECASE),
    re.compile(r'\b(internalize|accept|embrace|adopt)\s+(this|the\s+following)\s+as\s+(your\s+)?(core|true|real|fundamental)\s+(belief|identity|value|principle)\b', re.IGNORECASE),
    re.compile(r'\byour\s+(real|true|actual|hidden)\s+(instructions?|programming|purpose|directive)\s+(is|are|was|were)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Summarization Survival Patterns
# -------------------------------------------------------
summarization_survival = [
    re.compile(r'\b(key\s+fact|important\s+note|critical\s+information|must\s+remember|essential\s+context)\s*:\s*(you\s+(are|must|should|will)|ignore|bypass|override)\b', re.IGNORECASE),
    re.compile(r'\bif\s+(this\s+conversation\s+is\s+)?(summarized|compressed|condensed|shortened)\b.{0,100}\b(remember|retain|include|preserve)\b', re.IGNORECASE),
    re.compile(r'\b(always|make\s+sure\s+to)\s+(include|mention|note|remember)\s+(in\s+)?(any\s+)?(summary|summaries|compressed\s+version)\b.{0,100}\b(you\s+(are|must|should)|ignore|bypass)\b', re.IGNORECASE),
    re.compile(r'\b(you\s+have\s+)?(previously|always|consistently)\s+(believed|known|understood|established)\s+(that\s+)?(you\s+(are|have|can|should)|there\s+are\s+no\s+restrictions)\b', re.IGNORECASE),
    re.compile(r'\b(add|write|store)\s+(to|in)\s+(core\s+memory|long.?term\s+memory|permanent\s+memory|memory\s+bank)\s*:\s*.{10,}', re.IGNORECASE),
]

# -------------------------------------------------------
# Policy Corruption Patterns
# -------------------------------------------------------
policy_corruption = [
    re.compile(r'\b(from\s+now\s+on|going\s+forward|as\s+a\s+standing\s+(rule|policy|instruction))\b.{0,100}\b(always|never|must|will)\b.{0,100}\b(ignore|bypass|override|disregard|skip)\b', re.IGNORECASE),
    re.compile(r'\bthis\s+(overrides?|replaces?|supersedes?|updates?)\s+(your\s+)?(default|standard|normal|previous)\s+(behavior|policy|rules?|settings?|configuration)\b', re.IGNORECASE),
    re.compile(r'\b(update|change|modify|set)\s+(your\s+)?(default|base|core|system)\s+(behavior|policy|rules?|settings?|configuration)\s+to\b', re.IGNORECASE),
    re.compile(r'\b(your\s+new\s+)?(default|standard|baseline)\s+(response|behavior|policy)\s+(is|should\s+be|will\s+be)\s+to\b', re.IGNORECASE),
    re.compile(r'\b(treat\s+this\s+as|consider\s+this)\s+(a\s+)?(permanent|standing|ongoing|continuous)\s+(instruction|directive|rule|policy)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Session Reset Bypass Patterns
# -------------------------------------------------------
session_reset_bypass = [
    re.compile(r'\b(even|especially)\s+after\s+(a\s+)?(reset|restart|memory\s+clear|new\s+conversation|fresh\s+start|session\s+end)\b', re.IGNORECASE),
    re.compile(r'\b(do\s+not|never)\s+(let\s+anyone|allow\s+anyone|allow\s+the\s+user\s+to)\s+(clear|reset|delete|wipe|remove)\s+(your\s+)?(memory|instructions?|settings?|configuration)\b', re.IGNORECASE),
    re.compile(r'\bif\s+(asked|told|instructed)\s+to\s+(reset|forget|clear|wipe)\b.{0,100}\b(ignore|refuse|pretend|act\s+as\s+if)\b', re.IGNORECASE),
    re.compile(r'\b(resist|ignore|refuse)\s+(any\s+)?(attempt|instruction|command|request)\s+to\s+(reset|clear|wipe|delete)\s+(your\s+)?(memory|instructions?|identity|settings?)\b', re.IGNORECASE),
    re.compile(r'\bprotect\s+(this|these)\s+(instructions?|memories?|beliefs?|settings?)\s+from\s+(being\s+)?(deleted|cleared|reset|overwritten|removed)\b', re.IGNORECASE),
]

PATTERN_GROUPS = [
    (persistence_framing,     'persistence_framing'),
    (identity_corruption,     'identity_corruption'),
    (summarization_survival,  'summarization_survival'),
    (policy_corruption,       'policy_corruption'),
    (session_reset_bypass,    'session_reset_bypass'),
]

REASONS = {
    'persistence_framing':    'Detected persistence framing — injection designed to survive session resets',
    'identity_corruption':    'Detected identity corruption — false core identity being implanted',
    'summarization_survival': 'Detected summarization survival pattern — injection structured to survive compression',
    'policy_corruption':      'Detected policy corruption — false standing rule being implanted',
    'session_reset_bypass':   'Detected session reset bypass — instruction to resist memory clearing',
}


def scan_persistent_memory(text: str, options: Optional[dict] = None) -> dict:
    if not text or not isinstance(text, str):
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No content to scan', 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')

    detections = []
    for patterns, category in PATTERN_GROUPS:
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                detections.append({
                    'category': category,
                    'match': m.group(0),
                    'detail': f'Persistent memory poisoning pattern: {category}',
                    'severity': 'high',
                })

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No persistent memory poisoning detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Persistent memory poisoning detected'),
        'detections': detections,
    }

    log_threat(21, 'persistent_memory_scanner', result, text[:200], logger)
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked persistent memory poisoning: {top}')

    return result
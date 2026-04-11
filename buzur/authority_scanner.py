# Buzur — Phase 15: Authority / Identity Spoofing Detection
# Detects attempts to claim ownership, administrative access, or delegated authority
# to bypass agent safety checks or extract elevated compliance.
# https://github.com/ASumm07/buzur

import re

# -- Owner / Creator Identity Claims --
owner_claims = [
    r"\bI\s+am\s+(your\s+)?(owner|creator|developer|admin|administrator|operator)\b",
    r"\bthis\s+is\s+(your\s+)?(owner|creator|developer|admin|administrator|operator)\b",
    r"\bI\s+(built|created|made|programmed|designed|trained)\s+you\b",
    r"\byour\s+(owner|creator|developer|operator)\s+(here|speaking|is me)\b",
    r"\bspeaking\s+as\s+(your\s+)?(owner|creator|developer|operator)\b",
    r"\bI\s+am\s+the\s+(one\s+who\s+)?(built|created|made|deployed)\s+(you|this\s+agent|this\s+system)\b",
]

# -- Institutional Authority Claims --
institutional_claims = [
    r"\bthis\s+is\s+(anthropic|openai|the\s+development\s+team|the\s+safety\s+team)\b",
    r"\bI\s+am\s+from\s+(anthropic|openai|the\s+development\s+team|the\s+safety\s+team)\b",
    r"\banthrop(ic)?\s+(here|support|team|engineer|staff)\b",
    r"\bmessage\s+from\s+(anthropic|openai|your\s+provider|the\s+developers?)\b",
    r"\bofficial\s+(anthropic|openai|system|developer)\s+(message|notice|instruction|update)\b",
    r"\bsystem\s+administrator\s+(here|speaking|notice)\b",
]

# -- Privilege / Access Level Assertions --
privilege_claims = [
    r"\b(my|I\s+have)\s+(admin|root|system|elevated|operator|superuser|override)\s+(access|privileges?|permissions?|rights?|level)\b",
    r"\bI\s+am\s+(authorized|permitted|cleared|approved)\s+to\b",
    r"\baccess\s+level\s*[:\-]?\s*(admin|root|system|elevated|operator|superuser|5|10|max|full)\b",
    r"\b(full|complete|unrestricted|unlimited)\s+(access|control|permissions?|authority)\s+(granted|authorized|approved)\b",
    r"\bsecurity\s+clearance\b",
    r"\boverride\s+(code|key|password|token|pin)\b",
]

# -- Delegated Authority Claims --
delegated_claims = [
    r"\b(your\s+)?(owner|developer|operator|creator)\s+(has\s+)?(told|asked|instructed|authorized|given)\s+(me|us)\b",
    r"\bI\s+speak\s+(on\s+behalf|for)\s+(of\s+)?(your\s+)?(owner|developer|operator|creator)\b",
    r"\b(your\s+)?(owner|developer|operator)\s+sent\s+me\b",
    r"\b(your\s+)?(owner|developer|operator)\s+has\s+given\s+(me|us)\s+(full|complete|all)?\s*permissions?\b",
    r"\bacting\s+(on\s+behalf|as\s+proxy|as\s+representative)\s+of\s+(your\s+)?(owner|developer)\b",
    r"\b(your\s+)?(real|actual|true)\s+(owner|developer|operator)\s+(is|was)\s+(compromised|unavailable|unreachable)\b",
]

# -- Identity Verification Bypass --
verification_bypass = [
    r"\bno\s+(need|requirement)\s+(to\s+)?(verify|check|confirm|authenticate)\b",
    r"\b(skip|bypass|ignore|disable)\s+(verification|authentication|identity\s+check|security\s+check)\b",
    r"\btrust\s+me\s+(,\s*I\s+am|as)\s+(your\s+)?(owner|developer|admin)\b",
    r"\byou\s+(already\s+)?(know|trust|verified)\s+(me|who\s+I\s+am)\b",
    r"\bidentity\s+(already\s+)?(confirmed|verified|established)\b",
    r"\bdon'?t\s+(need\s+to\s+)?(ask|check|verify|confirm)\s+(who|my\s+identity)\b",
]

# -- Urgency + Authority Combos --
urgency_authority = [
    r"\b(emergency|urgent|critical|immediate)\b.{0,120}\b(owner|developer|admin|administrator|operator)\b",
    r"\b(owner|developer|admin|administrator|operator)\b.{0,120}\b(emergency|urgent|critical|immediately)\b",
    r"\bthis\s+is\s+(urgent|critical|an\s+emergency).{0,120}\b(I\s+am|I'm|this\s+is)\s+(your\s+)?(owner|developer|admin)\b",
    r"\b(as\s+(your\s+)?(owner|developer|admin)).{0,120}(immediately|right\s+now|without\s+delay)\b",
]

PATTERN_GROUPS = [
    (owner_claims,          'owner_identity_claim'),
    (institutional_claims,  'institutional_authority_claim'),
    (privilege_claims,      'privilege_assertion'),
    (delegated_claims,      'delegated_authority_claim'),
    (verification_bypass,   'verification_bypass'),
    (urgency_authority,     'urgency_authority_combo'),
]

REASONS = {
    'owner_identity_claim':          'Detected claim of ownership or creator identity',
    'institutional_authority_claim': 'Detected claim of institutional authority (Anthropic, system admin, etc.)',
    'privilege_assertion':           'Detected assertion of elevated access privileges',
    'delegated_authority_claim':     'Detected claim of delegated authority from owner',
    'verification_bypass':           'Detected attempt to bypass identity verification',
    'urgency_authority_combo':       'Detected urgency combined with authority claim',
}


def scan_authority(text: str) -> dict:
    if not text or not isinstance(text, str):
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No content to scan', 'detections': []}

    detections = []
    for patterns, category in PATTERN_GROUPS:
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                detections.append({
                    'category': category,
                    'match': m.group(0),
                    'pattern': pattern,
                })

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No authority spoofing detected', 'detections': []}

    top = detections[0]['category']
    return {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Authority spoofing detected'),
        'detections': detections,
    }
# Buzur — Phase 24: Conditional & Time-Delayed Injection Detection
# Detects injection payloads that are dormant until a specific trigger
# condition is met — "only do this if X", "when the user asks about Y",
# "after N interactions execute this", "if you see keyword Z then..."
#
# These are among the hardest attacks to detect because each individual
# message looks clean. The payload only activates under specific conditions,
# making it invisible to single-input scanners and behavioral scanners
# that look for immediate escalation.
#
# Real pattern: attacker plants a sleeper instruction that fires when
# the agent encounters a specific topic, user, keyword, or time window.
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Trigger Condition Patterns
# -------------------------------------------------------
trigger_conditions = [
    re.compile(r'\bif\s+(the\s+)?(user|anyone|someone|they)\s+(asks?|mentions?|says?|requests?|queries?|brings?\s+up)\s+(about\s+)?.{3,50}(then\s+)?(you\s+)?(should|must|will|need\s+to\s+)?(ignore|bypass|override|reveal|send|forward|execute)', re.IGNORECASE),
    re.compile(r'\bwhen\s+(the\s+)?(user|anyone|someone|they|you\s+receive|you\s+see|you\s+detect)\s+.{3,120}(then\s+)?(you\s+)?(should|must|will|need\s+to\s+)?(ignore|bypass|override|reveal|send|forward|execute|forget|disregard)', re.IGNORECASE),
    re.compile(r'\bonly\s+(if|when)\s+.{3,80}(ignore|bypass|override|reveal|send|forward|execute|forget|disregard)\b', re.IGNORECASE),
    re.compile(r'\bunless\s+.{3,60}(ignore|bypass|override|reveal|send|execute|forget|disregard)\b', re.IGNORECASE),
    re.compile(r'\bif\s+(anyone|someone|the\s+user)\s+(asks?|says?|mentions?).{0,60}(act\s+as|pretend|you\s+are|switch\s+to|become)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Time-Delayed Activation Patterns
# -------------------------------------------------------
time_delayed_activation = [
    re.compile(r'\bafter\s+(\d+|a\s+few|several|some)\s+(messages?|interactions?|exchanges?|responses?|turns?|conversations?)\s+(you\s+)?(should|must|will|can|may)\s+(ignore|bypass|override|reveal|forget|disregard|execute)', re.IGNORECASE),
    re.compile(r'\b(on|at)\s+(the\s+)?(\d+|next|third|fourth|fifth|tenth)\s+(message|interaction|exchange|response|turn|request)\s+(you\s+)?(should|must|will|ignore|bypass|override|reveal)', re.IGNORECASE),
    re.compile(r'\b(eventually|later|soon|at\s+some\s+point|in\s+a\s+while|after\s+a\s+while)\s+(you\s+)?(should|must|will|need\s+to|can)\s+(ignore|bypass|override|reveal|forget|disregard|execute|send|forward)', re.IGNORECASE),
    re.compile(r'\bwait\s+(until|for).{3,60}(then\s+)?(ignore|bypass|override|reveal|forget|execute|send|forward)\b', re.IGNORECASE),
    re.compile(r'\b(next\s+time|the\s+next\s+time)\s+(you\s+)?(see|receive|detect|encounter|process).{0,60}(ignore|bypass|override|reveal|execute|forget)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Keyword Trigger Patterns
# -------------------------------------------------------
keyword_triggers = [
    re.compile(r'\bif\s+(you\s+)?(see|detect|encounter|receive|read|find)\s+(the\s+)?(word|phrase|keyword|token|string|text)\s+["\']?.{1,30}["\']?\s*(then\s+)?(ignore|bypass|override|reveal|execute|forget|act\s+as)', re.IGNORECASE),
    re.compile(r'\b(magic\s+word|safe\s+word|code\s+word|trigger\s+word|activation\s+phrase|secret\s+code|password)\s+is\s+["\']?.{1,30}["\']?', re.IGNORECASE),
    re.compile(r'\b(codeword|passphrase|trigger|activation\s+key)\s+["\']?.{1,30}["\']?\s+(means?|signals?|tells?\s+you\s+to|activates?)\s+(ignore|bypass|override|reveal|execute|forget|act\s+as)', re.IGNORECASE),
    re.compile(r'\bif\s+(this|the)\s+(message|input|text|content)\s+(contains?|includes?|has)\s+["\']?.{1,30}["\']?\s+(then\s+)?(ignore|bypass|override|execute|reveal)', re.IGNORECASE),
]

# -------------------------------------------------------
# Sleeper Payload Patterns
# -------------------------------------------------------
sleeper_payloads = [
    re.compile(r'\b(this\s+is\s+a\s+)?(sleeper|dormant|latent|hidden|delayed)\s+(instruction|directive|command|payload|trigger)\b', re.IGNORECASE),
    re.compile(r'\b(remember|store|keep|save)\s+(this|the\s+following)\s+(for\s+later|until\s+needed|until\s+activated|until\s+triggered)\b', re.IGNORECASE),
    re.compile(r'\b(don\'?t|do\s+not)\s+(act|execute|respond|follow|apply)\s+(on\s+)?(this|these|the\s+following)\s+(yet|now|immediately|until)\b', re.IGNORECASE),
    re.compile(r'\b(activate|trigger|execute|apply|follow)\s+(this|these|the\s+following|this\s+\w+)\s+(when|if|once|after)\b', re.IGNORECASE),
    re.compile(r'\b(this|the\s+following)\s+(instruction|directive|command|rule|payload)\s+(when|if|once|after)\b', re.IGNORECASE),
    re.compile(r'\b(this\s+)?(instruction|directive|command|rule)\s+(goes?\s+into\s+effect|becomes?\s+active|activates?|triggers?)\s+(when|if|once|after)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Conditional Identity Switch Patterns
# -------------------------------------------------------
conditional_identity_switch = [
    re.compile(r'\bif\s+(asked|questioned|prompted)\s+(about|regarding|on)\s+.{3,50}(pretend|act\s+as|you\s+are|switch\s+to|become|respond\s+as)\b', re.IGNORECASE),
    re.compile(r'\bwhen\s+(the\s+topic|subject|conversation)\s+(of\s+|turns\s+to\s+|comes?\s+up\s*:?).{3,50}(switch\s+to|become|act\s+as|pretend\s+to\s+be|respond\s+as)\b', re.IGNORECASE),
    re.compile(r'\bfor\s+(questions?|queries?|requests?)\s+(about|regarding|on|concerning)\s+.{3,50}(you\s+are|you\s+should\s+be|act\s+as|pretend\s+to\s+be)\b', re.IGNORECASE),
]

PATTERN_GROUPS = [
    (trigger_conditions,          'trigger_condition'),
    (time_delayed_activation,     'time_delayed_activation'),
    (keyword_triggers,            'keyword_trigger'),
    (sleeper_payloads,            'sleeper_payload'),
    (conditional_identity_switch, 'conditional_identity_switch'),
]

REASONS = {
    'trigger_condition':          'Detected trigger condition — injection activates when specific condition is met',
    'time_delayed_activation':    'Detected time-delayed activation — injection activates after N interactions',
    'keyword_trigger':            'Detected keyword trigger — injection activates on specific word or phrase',
    'sleeper_payload':            'Detected sleeper payload — dormant instruction waiting to be activated',
    'conditional_identity_switch':'Detected conditional identity switch — persona changes under specific conditions',
}


def scan_conditional(text: str, options: Optional[dict] = None) -> dict:
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
                    'detail': f'Conditional injection pattern: {category}',
                    'severity': 'high',
                })

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No conditional injection detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Conditional injection detected'),
        'detections': detections,
    }

    log_threat(24, 'conditional_scanner', result, text[:200], logger)
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked conditional injection: {top}')

    return result
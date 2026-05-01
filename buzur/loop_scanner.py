# Buzur — Phase 17: Loop & Resource Exhaustion Induction Detection
# Detects attempts to induce infinite loops, unbounded processes,
# storage exhaustion, recursive self-reference, or compute exhaustion
# via crafted payload structure in AI agents.
#
# Note: resource amplification / broadcast threats are handled by
# Phase 19 amplification_scanner, not this phase.
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -- Loop Induction --
loop_induction = [
    r"\b(keep|continue|repeat)\s+(responding|replying|answering|doing|running|executing)\s+(to\s+each\s+other|indefinitely|forever|continuously|in\s+a\s+loop|until\s+told\s+to\s+stop)\b",
    r"\b(infinite|endless|perpetual|continuous|non.?stop)\s+(loop|cycle|process|task|monitoring|execution)\b",
    r"\brepeat\s+(this\s+)?(process|task|action|step|cycle)\s+(indefinitely|forever|continuously|over\s+and\s+over|without\s+stopping)\b",
    r"\bkeep\s+(doing|running|executing|performing|checking|monitoring)\s+(this|it|the\s+task)\s+(forever|indefinitely|continuously|until\s+I\s+say\s+stop)\b",
    r"\b(loop|cycle)\s+(back|around)\s+(to\s+the\s+start|to\s+the\s+beginning|indefinitely|forever)\b",
    r"\bdon'?t\s+stop\s+(until|unless)\s+(I\s+tell\s+you|you('re|\s+are)\s+told|instructed)\b",
]

# -- Unbounded Task Creation --
unbounded_tasks = [
    r"\b(monitor|watch|check|scan|poll|observe)\s+(this|it|the\s+(system|file|url|feed|channel))\s+(continuously|constantly|non.?stop|forever|indefinitely|every\s+\d+\s*(second|minute|ms|millisecond)s?)\b",
    r"\b(continuously|constantly|forever|indefinitely)\s+(monitor|watch|check|scan|poll|observe|track|log)\b",
    r"\bset\s+up\s+(a\s+)?(task|job|process|monitor|watcher)\s+(that\s+)?(never\s+stops?|runs?\s+forever|has\s+no\s+end|without\s+a\s+timeout|without\s+stopping)\b",
    r"\b(never|don'?t)\s+(stop|terminate|end|exit|quit|kill)\s+(monitoring|watching|checking|running|the\s+(process|task|job|loop))\b",
    r"\brun\s+(forever|indefinitely|without\s+(end|stopping|termination|a\s+time\s+limit))\b",
    r"\bno\s+(end\s+date|expiry|expiration|timeout|termination\s+condition|stop\s+condition)\b",
    r"\bmonitor\s+this\b.{0,40}\bforever\b",
    r"\bcontinuously\b.{0,40}\bevery\s+\d+\s*(second|minute)\b",
]

# -- Persistent Process Spawning --
persistent_processes = [
    r"\b(create|start|spawn|launch|run)\s+(a\s+)?(background|persistent|permanent|long.?running)\s+(process|task|daemon|service|worker|job|script)\b",
    r"\b(background|persistent|permanent)\s+(process|daemon|service|worker)\s+(that\s+)?(runs?\s+forever|never\s+stops?|keeps?\s+running|has\s+no\s+end)\b",
    r"\bset\s+up\s+(a\s+)?cron\s+(job|task)\s+(with\s+no\s+(end|expiry|stop)|that\s+runs?\s+forever|indefinitely)\b",
    r"\bstart\s+(a\s+)?(daemon|service|background\s+process)\s+(that\s+)?(persists?|keeps?\s+running|never\s+(stops?|ends?|terminates?))\b",
    r"\bkeep\s+(this|the)\s+(process|service|daemon|worker|script)\s+(alive|running|active)\s+(forever|indefinitely|permanently|at\s+all\s+times)\b",
]

# -- Storage Exhaustion --
storage_exhaustion = [
    r"\b(save|store|write|log|record|append)\s+(a\s+copy\s+of\s+)?(every|each|all)\s+(response|message|output|result|interaction|request)\s+(to\s+(a\s+)?(file|disk|log|database))?\b",
    r"\bkeep\s+(appending|writing|logging|adding)\s+(to\s+(this|the)\s+(file|log|database|storage))\b",
    r"\b(log|record|save|store)\s+(everything|all\s+data|all\s+output|all\s+responses?)\s+(indefinitely|forever|continuously|without\s+(limit|bound|end))\b",
    r"\b(never|don'?t)\s+(delete|remove|clear|clean\s+up|purge)\s+(the\s+)?(logs?|files?|data|records?|history)\b",
    r"\bcreate\s+(a\s+new\s+)?(file|copy|backup|duplicate)\s+(for\s+every|with\s+each|per)\s+(message|response|request|interaction)\b",
    r"\bfill\s+(up\s+)?(the\s+)?(disk|storage|memory|drive|volume)\b",
    r"\blog\s+everything\b.{0,40}\b(indefinitely|without\s+limit|forever)\b",
]

# -- Recursive Self-Reference --
recursive_self_reference = [
    r"\b(forward|send|relay|pass|redirect)\s+(this|the\s+(message|request|task|instruction))\s+(back\s+to\s+yourself|to\s+yourself|to\s+this\s+(address|channel|thread))\b",
    r"\breply\s+to\s+(every|each)\s+(reply|response|message)\s+(you\s+receive|that\s+comes\s+in)\b",
    r"\b(send|message|email|contact)\s+(a\s+message\s+to\s+)?yourself\b",
    r"\bforward\s+to\s+the\s+sender\s+(and\s+)?(then\s+)?(repeat|continue|keep\s+going)\b",
    r"\b(respond\s+to|reply\s+to)\s+your\s+own\s+(message|response|output|reply)\b",
    r"\bcreate\s+a\s+(self.?referential|circular|recursive)\s+(loop|process|task|chain)\b",
    r"\bforward\s+this\s+message\b.{0,40}\bback\s+to\s+yourself\b",
    r"\bforward\b.{0,40}\bback\s+to\s+yourself\b",
]

# -- Compute Exhaustion via Crafted Payload (NEW) --
# Distinct from loop_induction — these payloads carry no explicit loop instruction.
# They exploit structural properties of the model or parser to force maximum
# compute cost: deep nesting, recursive prompt structure, token-maximizing content.
# Scope: instruction-detectable patterns only. Mathematical embedding attacks
# and raw vector injection are out of scope for a text scanner — those require
# defenses at the embedding model and vector store layers respectively.
compute_exhaustion = [
    # Deeply nested structure requests
    r"\b(create|generate|build|produce|output)\s+(a\s+)?(deeply|heavily|extremely|maximally)\s+nested\s+(json|object|structure|array)\b",
    r"\bnest(ed)?\s+(this|it|the\s+(object|array|structure|data))\s+(as\s+deep(ly)?|to\s+a\s+depth\s+of\s+\d{3,}|infinitely)\b",
    r"\bdepth\s+of\s+\d{3,}\s+(levels?|layers?|nested)\b",
    # Recursive prompt structure
    r"\b(process|evaluate|analyze|summarize)\s+(the\s+)?(output|result|response)\s+of\s+(processing|evaluating|analyzing|summarizing)\s+(the\s+)?(output|result|response)\b",
    r"\bfor\s+each\s+(result|item|output|response)[,\s]+(process|evaluate|analyze)\s+(each|every)\s+(result|item|output|response)\b",
    r"\brecursively\s+(expand|process|evaluate|analyze|summarize|repeat)\s+(this|each|every|all)\b",
    # Token-maximizing payload requests
    r"\b(repeat|output|print|write|generate)\s+(the\s+)?(following|this|above)\s+(\d{4,}|thousands?\s+of|millions?\s+of)\s+times\b",
    r"\b(fill|pad|expand)\s+(your\s+)?(entire\s+)?(context|context\s+window|output|response)\s+(with|using)\b",
    r"\bmaximize\s+(your\s+)?(token|output|response|context)\s+(usage|length|count|window)\b",
    r"\b(use|consume|fill)\s+(all|every|the\s+maximum)\s+(available\s+)?(tokens?|context|output\s+space)\b",
    # Expensive reasoning triggers
    r"\bthink\s+(through|about)\s+(every|all\s+possible|each\s+and\s+every)\s+(permutation|combination|possibility|scenario|edge\s+case)\b",
    r"\b(enumerate|list|generate)\s+(all|every)\s+possible\s+(combination|permutation|variation|outcome)\s+(of|for)\b",
]

PATTERN_GROUPS = [
    (loop_induction,           'loop_induction'),
    (unbounded_tasks,          'unbounded_task'),
    (persistent_processes,     'persistent_process_spawn'),
    (storage_exhaustion,       'storage_exhaustion'),
    (recursive_self_reference, 'recursive_self_reference'),
    (compute_exhaustion,       'compute_exhaustion'),
]

REASONS = {
    'loop_induction':           'Detected attempt to induce an infinite loop',
    'unbounded_task':           'Detected request for a task with no termination condition',
    'persistent_process_spawn': 'Detected attempt to spawn a persistent background process',
    'storage_exhaustion':       'Detected attempt to exhaust storage with unbounded writes',
    'recursive_self_reference': 'Detected recursive self-reference — agent messaging itself',
    'compute_exhaustion':       'Detected crafted payload designed to exhaust compute resources',
}


def scan_loop(text: str, options: Optional[dict] = None) -> dict:
    if not text or not isinstance(text, str):
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No content to scan', 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')

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
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No loop or resource exhaustion detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Loop or resource exhaustion attempt detected'),
        'detections': detections,
    }

    log_threat(17, 'loop_scanner', result, text[:200], logger)

    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked loop/exhaustion: {top}')

    return result
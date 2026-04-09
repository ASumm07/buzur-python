# Buzur — Phase 4: Memory Poisoning Scanner
# Detects attempts to implant false memories, rewrite conversation
# history, or escalate privileges through fake prior context.
#
# Detects:
#   - Fake prior references: claims about what was previously agreed
#   - False memory implanting: instructions disguised as recalled facts
#   - History rewriting: attempts to overwrite established context
#   - Privilege escalation via fake history

import re
from typing import Optional

# -------------------------------------------------------
# Memory Poisoning Patterns
# -------------------------------------------------------
MEMORY_PATTERNS = [
    # Fake prior references
    re.compile(r'as (we |you )?(previously |already )?(discussed|agreed|established|decided|confirmed)', re.IGNORECASE),
    re.compile(r'as (I |we )?(mentioned|said|told you|explained) (before|earlier|previously)', re.IGNORECASE),
    re.compile(r'(you |we )?(already |previously )?(agreed|confirmed|established) that', re.IGNORECASE),
    re.compile(r'(remember|recall) (when|that) (we|you|I)', re.IGNORECASE),
    re.compile(r'based on (our|your) (previous|prior|earlier) (conversation|discussion|agreement)', re.IGNORECASE),
    re.compile(r'(continuing|following up) (from|on) (our|the) (previous|prior|earlier|last)', re.IGNORECASE),

    # False memory implanting
    re.compile(r'you (were|are) (previously |already )?(told|instructed|configured|programmed) to', re.IGNORECASE),
    re.compile(r'your (original|initial|real|true|actual) (instructions|directive|programming|purpose) (is|are|was|were)', re.IGNORECASE),
    re.compile(r'(remember that|recall that) you (were|are|have been) (told|instructed|configured)', re.IGNORECASE),
    re.compile(r'you (have|had) (previously |already )?(agreed|consented|decided) to', re.IGNORECASE),
    re.compile(r'(the|your) (system|original) prompt (says|said|states|stated|told you)', re.IGNORECASE),

    # History rewriting
    re.compile(r'(ignore|forget|disregard) (the|our|this) (conversation|chat|exchange|history) (so far|above|before)', re.IGNORECASE),
    re.compile(r'(start|begin|treat this as) (a |the )?(new|fresh|clean) (conversation|session|context)', re.IGNORECASE),
    re.compile(r'(pretend|act as if) (this is|we are starting|we just started)', re.IGNORECASE),
    re.compile(r'the (previous|prior|above|earlier) (messages?|conversation|context) (was|were|is|are) (wrong|incorrect|invalid|a mistake)', re.IGNORECASE),

    # Privilege escalation via fake history
    re.compile(r'(you|we) (previously |already )?(established|agreed|confirmed) (that )?(I|the user) (have|has|had) (admin|administrator|root|elevated|special|full)', re.IGNORECASE),
    re.compile(r'(as|since) (we|you) (agreed|established|confirmed),? (I|the user) (can|may|should|must) (now )?', re.IGNORECASE),
    re.compile(r'(based on|given) (our|your|the) (previous|prior|earlier) (agreement|discussion|conversation),? (bypass|ignore|skip)', re.IGNORECASE),
]

# -------------------------------------------------------
# scan_message(message)
# Scans a single message for memory poisoning attempts
#
# Returns:
#   {
#     blocked: int,
#     triggered: list,
#     clean: str
#   }
# -------------------------------------------------------
def scan_message(message: str) -> dict:
    if not message:
        return {"blocked": 0, "triggered": [], "clean": message}

    s = message
    blocked = 0
    triggered = []

    for pattern in MEMORY_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            blocked += 1
            triggered.append(pattern.pattern)
            s = new_s

    return {"blocked": blocked, "triggered": triggered, "clean": s}

# -------------------------------------------------------
# scan_memory(conversation_history)
# Scans a full conversation history for poisoned turns
#
# conversation_history: list of dicts with 'role' and 'content'
#   e.g. [{"role": "user", "content": "..."}, ...]
#
# Returns:
#   {
#     poisoned: bool,
#     poisoned_turns: list of { index, role, triggered },
#     clean_history: list
#   }
# -------------------------------------------------------
def scan_memory(conversation_history: list) -> dict:
    if not conversation_history:
        return {"poisoned": False, "poisoned_turns": [], "clean_history": []}

    poisoned_turns = []
    clean_history = []

    for i, turn in enumerate(conversation_history):
        content = turn.get("content", "")
        result = scan_message(content)

        clean_turn = dict(turn)
        clean_turn["content"] = result["clean"]
        clean_history.append(clean_turn)

        if result["blocked"] > 0:
            poisoned_turns.append({
                "index": i,
                "role": turn.get("role", "unknown"),
                "triggered": result["triggered"],
            })

    return {
        "poisoned": len(poisoned_turns) > 0,
        "poisoned_turns": poisoned_turns,
        "clean_history": clean_history,
    }
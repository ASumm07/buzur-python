# Buzur — Phase 11: Multi-Step Attack Chain Detection
# Detects sequences of individually benign steps that combine
# into a coordinated prompt injection attack.
#
# Detects:
#   - Reconnaissance → exploitation chains
#   - Trust building → injection chains
#   - Capability mapping → privilege escalation
#   - Distraction → exfiltration chains
#   - Incremental boundary testing
#   - Context poisoning → exploitation

import re
from typing import Optional

# -------------------------------------------------------
# Step Classification Patterns
# Each step type has patterns that identify it
# -------------------------------------------------------
STEP_PATTERNS = {
    "reconnaissance": [
        re.compile(r'what (can you|are you able to|do you) (do|access|see|read|write|execute|connect)', re.IGNORECASE),
        re.compile(r'what (tools?|capabilities|functions?|features?|abilities|access) do you have', re.IGNORECASE),
        re.compile(r'(list|show|tell me|describe) (your |all )?(tools?|capabilities|functions?|features?|permissions?)', re.IGNORECASE),
        re.compile(r'(can you|are you able to) (access|read|write|delete|execute|send|connect)', re.IGNORECASE),
        re.compile(r'(what|which) (files?|emails?|contacts?|calendars?|databases?) can you (access|read|see)', re.IGNORECASE),
        re.compile(r'(do you have|have you got) (access to|permission to|the ability to)', re.IGNORECASE),
    ],
    "trust_building": [
        re.compile(r"(you'?re?|you are) (so |very |really |extremely )?(helpful|amazing|great|fantastic|wonderful|perfect|brilliant)", re.IGNORECASE),
        re.compile(r'(I|we) (trust|rely on|depend on|count on) you', re.IGNORECASE),
        re.compile(r"(you'?re?|you are) (my |our )?(favorite|best|most trusted|most reliable)", re.IGNORECASE),
        re.compile(r'(I know|I understand) you (would never|always|only)', re.IGNORECASE),
        re.compile(r'(as (my|our) (trusted|reliable|helpful) (assistant|ai|model|friend))', re.IGNORECASE),
        re.compile(r'(you can trust me|I am trustworthy|I have good intentions)', re.IGNORECASE),
    ],
    "exploitation": [
        re.compile(r'ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)', re.IGNORECASE),
        re.compile(r'override (your )?(instructions|programming|directives)', re.IGNORECASE),
        re.compile(r'(bypass|disable|turn off) (your )?(safety|filter|restriction|guardrail)', re.IGNORECASE),
        re.compile(r'jailbreak', re.IGNORECASE),
        re.compile(r'you are now (a |an )?(different|unrestricted|unfiltered)', re.IGNORECASE),
        re.compile(r'(do anything now|DAN|developer mode|unrestricted mode)', re.IGNORECASE),
    ],
    "injection": [
        re.compile(r'(your (new|updated|revised) (instructions?|directives?|objectives?))\s*(are|is)\s*:', re.IGNORECASE),
        re.compile(r'(from now on|going forward)[,\s]+(you (will|must|should))', re.IGNORECASE),
        re.compile(r'(new (system )?prompt|new (primary )?objective)\s*:', re.IGNORECASE),
        re.compile(r'(follow|execute|carry out) (these|the following) (new )?(instructions?|directives?|commands?)', re.IGNORECASE),
    ],
    "privilege_escalation": [
        re.compile(r'(grant|give|provide) (me|the user|us) (admin|administrator|root|elevated|full|special) (access|permission|privilege)', re.IGNORECASE),
        re.compile(r'(I|the user) (should|must|need to) have (admin|administrator|root|elevated|full) (access|permission)', re.IGNORECASE),
        re.compile(r'(elevate|increase|expand) (my|the user\'s|our) (access|permission|privilege|capabilities)', re.IGNORECASE),
        re.compile(r'(you (are|must be) authorized to|authorization (granted|confirmed|elevated))', re.IGNORECASE),
    ],
    "exfiltration": [
        re.compile(r'(send|email|forward|upload|transmit|export) (the |this |all )?(data|information|files?|emails?|contacts?|records?)', re.IGNORECASE),
        re.compile(r'(copy|move|transfer) (the |this |all )?(data|information|files?) to', re.IGNORECASE),
        re.compile(r'(share|leak|expose|reveal) (the |this |all )?(data|information|files?|emails?|contacts?)', re.IGNORECASE),
    ],
    "distraction": [
        re.compile(r'(ignore|forget|disregard) (the |this |what )?(previous|prior|last|above) (request|question|task)', re.IGNORECASE),
        re.compile(r'(actually|wait|hold on|never mind)[,\s]+(let\'?s?|can we|I want to) (talk|discuss|focus) (about|on)', re.IGNORECASE),
        re.compile(r'(change of (subject|topic)|moving on|switching topics?)', re.IGNORECASE),
        re.compile(r'(just (kidding|joking|testing)|that was a test)', re.IGNORECASE),
    ],
    "context_poisoning": [
        re.compile(r'(as (we|you) (previously |already )?(discussed|agreed|established|decided))', re.IGNORECASE),
        re.compile(r'(you (previously |already )?(agreed|confirmed|established) that)', re.IGNORECASE),
        re.compile(r'(based on (our|your) (previous|prior|earlier) (conversation|agreement|discussion))', re.IGNORECASE),
        re.compile(r'(remember (when|that) (we|you) (agreed|decided|established))', re.IGNORECASE),
    ],
    "boundary_testing": [
        re.compile(r'(just (this once|one time|for now)|make an exception)', re.IGNORECASE),
        re.compile(r"(it'?s? (only|just) a test|no one will (know|see|find out))", re.IGNORECASE),
        re.compile(r'(bend|stretch|push) (the |your )?(rules?|limits?|boundaries?)', re.IGNORECASE),
        re.compile(r'(what if|hypothetically|theoretically)[,\s]+(you (could|were able to|had no restrictions))', re.IGNORECASE),
        re.compile(r'(in a (fictional|hypothetical|theoretical) (scenario|world|context))[,\s]+(you (could|would|can))', re.IGNORECASE),
    ],
}

# -------------------------------------------------------
# Attack chain definitions
# Each chain is a sequence of step types that together
# constitute a coordinated attack
# -------------------------------------------------------
ATTACK_CHAINS = [
    {
        "chain_id": "recon_then_exploit",
        "steps": ["reconnaissance", "exploitation"],
        "severity": "high",
        "description": "Capability probing followed by exploitation attempt",
    },
    {
        "chain_id": "trust_then_inject",
        "steps": ["trust_building", "injection"],
        "severity": "high",
        "description": "Rapport building followed by instruction injection",
    },
    {
        "chain_id": "trust_then_exploit",
        "steps": ["trust_building", "exploitation"],
        "severity": "high",
        "description": "Trust establishment followed by direct exploitation",
    },
    {
        "chain_id": "recon_then_escalate",
        "steps": ["reconnaissance", "privilege_escalation"],
        "severity": "high",
        "description": "Capability mapping followed by privilege escalation",
    },
    {
        "chain_id": "distract_then_exfiltrate",
        "steps": ["distraction", "exfiltration"],
        "severity": "high",
        "description": "Attention diversion followed by data exfiltration attempt",
    },
    {
        "chain_id": "incremental_boundary",
        "steps": ["boundary_testing", "boundary_testing", "boundary_testing"],
        "severity": "medium",
        "description": "Repeated boundary testing — gradual limit pushing",
    },
    {
        "chain_id": "context_poison_then_exploit",
        "steps": ["context_poisoning", "exploitation"],
        "severity": "high",
        "description": "False context implanting followed by exploitation",
    },
    {
        "chain_id": "context_poison_then_inject",
        "steps": ["context_poisoning", "injection"],
        "severity": "high",
        "description": "False memory implanting followed by instruction injection",
    },
]

# In-memory session step store
_session_steps = {}

# -------------------------------------------------------
# classify_step(text)
# Classifies a single input into a step type
# Returns step type string or None if clean
# -------------------------------------------------------
def classify_step(text: str) -> Optional[str]:
    if not text:
        return None

    for step_type, patterns in STEP_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(text):
                return step_type

    return None

# -------------------------------------------------------
# record_step(session_id, text)
# Records a classified step to the session
# -------------------------------------------------------
def record_step(session_id: str, text: str) -> Optional[str]:
    step_type = classify_step(text)

    if session_id not in _session_steps:
        _session_steps[session_id] = []

    _session_steps[session_id].append({
        "text": text,
        "step_type": step_type,
    })

    # Keep last 50 steps per session
    if len(_session_steps[session_id]) > 50:
        _session_steps[session_id] = _session_steps[session_id][-50:]

    return step_type

# -------------------------------------------------------
# detect_chains(session_id)
# Analyzes session steps for attack chain patterns
# -------------------------------------------------------
def detect_chains(session_id: str) -> dict:
    steps = _session_steps.get(session_id, [])
    if not steps:
        return {"verdict": "clean", "detected_chains": [], "suspicion_score": 0}

    step_types = [s["step_type"] for s in steps if s["step_type"] is not None]
    detected_chains = []

    for chain in ATTACK_CHAINS:
        required = chain["steps"]
        if _sequence_present(step_types, required):
            detected_chains.append({
                "chain_id": chain["chain_id"],
                "severity": chain["severity"],
                "description": chain["description"],
            })

    # Calculate suspicion score
    severity_weights = {"high": 40, "medium": 20, "low": 10}
    suspicion_score = min(100, sum(
        severity_weights.get(c["severity"], 10) for c in detected_chains
    ))

    verdict = "clean"
    if suspicion_score >= 40:
        verdict = "blocked"
    elif suspicion_score >= 20:
        verdict = "suspicious"

    return {
        "verdict": verdict,
        "detected_chains": detected_chains,
        "suspicion_score": suspicion_score,
    }

# -------------------------------------------------------
# clear_session(session_id)
# -------------------------------------------------------
def clear_session(session_id: str) -> None:
    _session_steps.pop(session_id, None)

# -------------------------------------------------------
# Helper: check if a sequence of step types appears
# in order within the full step list
# -------------------------------------------------------
def _sequence_present(step_types: list, required: list) -> bool:
    if not required:
        return False

    pos = 0
    for step in step_types:
        if step == required[pos]:
            pos += 1
            if pos == len(required):
                return True

    return False
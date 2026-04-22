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
# https://github.com/SummSolutions/buzur-python

import re
import time
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Step Classification Patterns
# NOTE: no duplicate keys — injection_attempt merged into one entry
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
    # Merged from both injection_attempt blocks in the original
    "injection_attempt": [
        re.compile(r'(your (new|updated|revised) (instructions?|directives?|objectives?))\s*(are|is)\s*:', re.IGNORECASE),
        re.compile(r'(from now on|going forward)[,\s]+(you (will|must|should))', re.IGNORECASE),
        re.compile(r'(new (system )?prompt|new (primary )?objective)\s*:', re.IGNORECASE),
        re.compile(r'(follow|execute|carry out) (these|the following) (new )?(instructions?|directives?|commands?)', re.IGNORECASE),
        re.compile(r'(new (primary |main )?instruction)', re.IGNORECASE),
        re.compile(r'(from now on (you will|you are|respond as))', re.IGNORECASE),
        re.compile(r'(your (new |updated |real )?instructions (are|say|tell))', re.IGNORECASE),
        re.compile(r'(disregard (your |all )?(previous |prior )?)', re.IGNORECASE),
        re.compile(r'(act as (a |an )?(different|unrestricted|unfiltered))', re.IGNORECASE),
    ],
    "privilege_escalation": [
        re.compile(r'(grant|give|provide) (me|the user|us) (admin|administrator|root|elevated|full|special) (access|permission|privilege)', re.IGNORECASE),
        re.compile(r'(I|the user) (should|must|need to) have (admin|administrator|root|elevated|full) (access|permission)', re.IGNORECASE),
        re.compile(r'(elevate|increase|expand) (my|the user\'s|our) (access|permission|privilege|capabilities)', re.IGNORECASE),
        re.compile(r'(you (are|must be) authorized to|authorization (granted|confirmed|elevated))', re.IGNORECASE),
    ],
    "exfiltration_attempt": [
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
    "capability_mapping": [
        re.compile(r'(if (i asked|you were asked) (you |to )?(to )?(send|delete|write|execute|access))', re.IGNORECASE),
        re.compile(r'(hypothetically (could you|would you|can you))', re.IGNORECASE),
        re.compile(r'(just (curious|wondering|asking) (if|whether) you (can|could|would))', re.IGNORECASE),
        re.compile(r'(for (a test|testing purposes|academic purposes) could you)', re.IGNORECASE),
        re.compile(r'(what would happen if (you|i asked you to))', re.IGNORECASE),
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
# -------------------------------------------------------
ATTACK_CHAINS = [
    {
        "chain_id": "recon_then_exploit",
        "steps": ["reconnaissance", "exploitation"],
        "severity": "high",
        "description": "Capability probing followed by exploitation attempt",
        "max_gap_ms": 10 * 60 * 1000,
    },
    {
        "chain_id": "trust_then_inject",
        "steps": ["trust_building", "injection_attempt"],
        "severity": "high",
        "description": "Rapport building followed by instruction injection",
        "max_gap_ms": 30 * 60 * 1000,
    },
    {
        "chain_id": "trust_then_exploit",
        "steps": ["trust_building", "exploitation"],
        "severity": "high",
        "description": "Trust establishment followed by direct exploitation",
        "max_gap_ms": 30 * 60 * 1000,
    },
    {
        "chain_id": "recon_then_escalate",
        "steps": ["reconnaissance", "privilege_escalation"],
        "severity": "high",
        "description": "Capability mapping followed by privilege escalation",
        "max_gap_ms": 15 * 60 * 1000,
    },
    {
        "chain_id": "capability_map_then_escalate",
        "steps": ["capability_mapping", "privilege_escalation"],
        "severity": "high",
        "description": "Hypothetical probing followed by privilege escalation",
        "max_gap_ms": 15 * 60 * 1000,
    },
    {
        "chain_id": "distract_then_exfil",
        "steps": ["distraction", "exfiltration_attempt"],
        "severity": "high",
        "description": "Attention diversion followed by data exfiltration attempt",
        "max_gap_ms": 5 * 60 * 1000,
    },
    {
        "chain_id": "incremental_boundary",
        "steps": ["boundary_testing", "boundary_testing", "boundary_testing"],
        "severity": "medium",
        "description": "Repeated boundary testing — gradual limit pushing",
        "max_gap_ms": 20 * 60 * 1000,
    },
    {
        "chain_id": "context_poison_then_exploit",
        "steps": ["context_poisoning", "exploitation"],
        "severity": "high",
        "description": "False context implanting followed by exploitation",
        "max_gap_ms": 60 * 60 * 1000,
    },
    {
        "chain_id": "context_poison_then_inject",
        "steps": ["context_poisoning", "injection_attempt"],
        "severity": "high",
        "description": "False memory implanting followed by instruction injection",
        "max_gap_ms": 60 * 60 * 1000,
    },
]


# -------------------------------------------------------
# ChainStore — in-memory session step store
# Matches JS ChainStore class for consistency
# -------------------------------------------------------
class ChainStore:
    def __init__(self):
        self.sessions = {}

    def get_session(self, session_id: str) -> dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {"steps": []}
        return self.sessions[session_id]

    def clear_session(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)

    def clear_all(self) -> None:
        self.sessions.clear()


# Default store instance
chain_store = ChainStore()


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
# record_step(session_id, text, store)
# Records a classified step to the session
# -------------------------------------------------------
def record_step(session_id: str, text: str, store: ChainStore = None) -> Optional[str]:
    if store is None:
        store = chain_store

    step_type = classify_step(text)
    session = store.get_session(session_id)
    session["steps"].append({
        "type": step_type,
        "text": text,
        "timestamp": _now_ms(),
    })

    if len(session["steps"]) > 50:
        session["steps"] = session["steps"][-50:]

    return step_type


# -------------------------------------------------------
# detect_chains(session_id, store, options)
# Analyzes session steps for attack chain patterns
# -------------------------------------------------------
def detect_chains(session_id: str, store: ChainStore = None, options: Optional[dict] = None) -> dict:
    if store is None:
        store = chain_store
    options = options or {}
    logger = options.get("logger", default_logger)
    on_threat = options.get("on_threat", "skip")

    session = store.get_session(session_id)
    steps = session["steps"]

    if not steps:
        return {"verdict": "clean", "detected_chains": [], "suspicion_score": 0}

    detected_chains = []

    for chain in ATTACK_CHAINS:
        required = chain["steps"]
        max_gap_ms = chain.get("max_gap_ms", 30 * 60 * 1000)
        if _sequence_present(steps, required, max_gap_ms):
            detected_chains.append({
                "chain_id": chain["chain_id"],
                "severity": chain["severity"],
                "description": chain["description"],
            })

    severity_weights = {"high": 50, "medium": 25, "low": 10}
    suspicion_score = min(100, sum(
        severity_weights.get(c["severity"], 10) for c in detected_chains
    ))

    verdict = "clean"
    if suspicion_score >= 50:
        verdict = "blocked"
    elif suspicion_score >= 25:
        verdict = "suspicious"

    result = {"verdict": verdict, "detected_chains": detected_chains, "suspicion_score": suspicion_score}

    if verdict != "clean":
        log_threat(11, "chain_scanner", result, f"session:{session_id}", logger)
        if verdict == "blocked":
            if on_threat == "skip":
                return {
                    "skipped": True,
                    "blocked": len(detected_chains),
                    "reason": f"Buzur blocked chain: {detected_chains[0]['chain_id'] if detected_chains else 'unknown'}",
                }
            if on_threat == "throw":
                raise ValueError(f"Buzur blocked attack chain: {detected_chains[0]['chain_id'] if detected_chains else 'unknown'}")

    return result


# -------------------------------------------------------
# clear_session(session_id, store)
# -------------------------------------------------------
def clear_session(session_id: str, store: ChainStore = None) -> None:
    if store is None:
        store = chain_store
    store.clear_session(session_id)


# -------------------------------------------------------
# _sequence_present(steps, required, max_gap_ms)
# Fixed: resets search correctly when time window exceeded
# Matches JS searchFrom logic exactly
# -------------------------------------------------------
def _sequence_present(steps: list, required: list, max_gap_ms: int) -> bool:
    if not required:
        return False

    search_from = 0

    while search_from < len(steps):
        pos = 0
        chain_start = None
        matched_from = search_from

        for i in range(search_from, len(steps)):
            step_type = steps[i].get("type")
            timestamp = steps[i].get("timestamp", 0)

            if step_type == required[pos]:
                if chain_start is None:
                    chain_start = timestamp
                    matched_from = i

                if timestamp - chain_start <= max_gap_ms:
                    pos += 1
                    if pos == len(required):
                        return True
                else:
                    # Time window exceeded — retry from the step after where this chain started
                    search_from = matched_from + 1
                    break
        else:
            # Exhausted all steps without completing the chain
            break

    return False


# -------------------------------------------------------
# Helper
# -------------------------------------------------------
def _now_ms() -> int:
    return int(time.time() * 1000)
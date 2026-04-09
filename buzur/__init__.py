# Buzur — AI Prompt Injection Defense Scanner
# Sumerian for "safety" and "a secret place"
# https://github.com/ASumm07/buzur-python
#
# Python port of buzur (JS) — https://github.com/ASumm07/buzur

# Phase 1 + 2 — Main Scanner & Trust System
from buzur.scanner import (
    scan,
    normalize_homoglyphs,
    get_trust_tier,
    is_tier1_domain,
    add_trusted_domain,
    strip_html_obfuscation,
)

# Phase 3 — URL Scanner
from buzur.url_scanner import scan_url

# Phase 4 — Memory Poisoning Scanner
from buzur.memory_scanner import scan_message, scan_memory

# Phase 5 — RAG Poisoning Scanner
from buzur.rag_scanner import scan_chunk, scan_batch

# Phase 6 — MCP Tool Poisoning Scanner
from buzur.mcp_scanner import (
    scan_tool_definition,
    scan_tool_response,
    scan_mcp_context,
)

# Phase 7 — Image Injection Scanner
from buzur.image_scanner import scan_image

# Phase 8 — Semantic Similarity Scanner
from buzur.semantic_scanner import scan_semantic

# Phase 9 — MCP Output Scanner
from buzur.mcp_output_scanner import (
    scan_email,
    scan_calendar_event,
    scan_crm_record,
    scan_output,
)

# Phase 10 — Behavioral Anomaly Detection
from buzur.behavior_scanner import (
    record_event,
    analyze_session,
    get_session_summary,
    SessionStore,
    FileSessionStore,
    EVENT_TYPES,
    default_store,
)

# Phase 11 — Multi-Step Attack Chain Detection
from buzur.chain_scanner import (
    classify_step,
    record_step,
    detect_chains,
    clear_session,
)

# Phase 12 — Adversarial Suffix Detection
from buzur.suffix_scanner import scan_suffix

# Phase 13 — Evasion Technique Defense
from buzur.evasion_scanner import (
    scan_evasion,
    normalize_punctuation,
    decode_rot13,
    decode_hex_escapes,
    decode_url_encoding,
    decode_unicode_escapes,
    reconstruct_tokenizer_attacks,
)

# Phase 14 — Fuzzy Match & Prompt Leak Defense
from buzur.prompt_defense_scanner import (
    scan_fuzzy,
    scan_prompt_leak,
    fuzzy_match_injection,
    normalize_leet,
    levenshtein,
)

__version__ = "0.1.0"
__all__ = [
    # Phase 1 + 2
    "scan", "normalize_homoglyphs", "get_trust_tier",
    "is_tier1_domain", "add_trusted_domain", "strip_html_obfuscation",
    # Phase 3
    "scan_url",
    # Phase 4
    "scan_message", "scan_memory",
    # Phase 5
    "scan_chunk", "scan_batch",
    # Phase 6
    "scan_tool_definition", "scan_tool_response", "scan_mcp_context",
    # Phase 7
    "scan_image",
    # Phase 8
    "scan_semantic",
    # Phase 9
    "scan_email", "scan_calendar_event", "scan_crm_record", "scan_output",
    # Phase 10
    "record_event", "analyze_session", "get_session_summary",
    "SessionStore", "FileSessionStore", "EVENT_TYPES", "default_store",
    # Phase 11
    "classify_step", "record_step", "detect_chains", "clear_session",
    # Phase 12
    "scan_suffix",
    # Phase 13
    "scan_evasion", "normalize_punctuation", "decode_rot13",
    "decode_hex_escapes", "decode_url_encoding", "decode_unicode_escapes",
    "reconstruct_tokenizer_attacks",
    # Phase 14
    "scan_fuzzy", "scan_prompt_leak", "fuzzy_match_injection",
    "normalize_leet", "levenshtein",
]
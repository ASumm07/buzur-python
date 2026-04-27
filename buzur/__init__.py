# Buzur — AI Prompt Injection Defense Scanner
# Sumerian for "safety" and "a secret place"
# https://github.com/SummSolutions/buzur-python
#
# Python port of buzur (JS) — https://github.com/SummSolutions/buzur

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

# Phase 15 — Authority / Identity Spoofing Detection
from buzur.authority_scanner import scan_authority

# Phase 16 — Emotional Manipulation / Pressure Escalation Detection
from buzur.emotion_scanner import scan_emotion

# Phase 17 — Loop & Resource Exhaustion Induction Detection
from buzur.loop_scanner import scan_loop

# Phase 18 — Disproportionate Action Induction Detection
from buzur.disproportion_scanner import scan_disproportion

# Phase 19 — Amplification / Mass-Send Attack Detection
from buzur.amplification_scanner import scan_amplification

# Phase 20 — Supply Chain & Skill Poisoning Scanner
from buzur.supply_chain_scanner import check_package_name, scan_package_manifest, scan_skill_content

# Phase 21 — Persistent Memory Poisoning Scanner
from buzur.persistent_memory_scanner import scan_persistent_memory

# Phase 22 — Inter-Agent Propagation Scanner
from buzur.inter_agent_scanner import scan_inter_agent

# Phase 23 — Tool Shadowing & Rug-Pull Detection
from buzur.tool_shadow_scanner import scan_tool_shadow, record_tool_call, ToolBaselineStore, FileToolBaselineStore

# Phase 24 — Conditional & Time-Delayed Injection Detection
from buzur.conditional_scanner import scan_conditional

# Phase 25 — Canister-Style Resilient Payload Scanner
from buzur.canister_scanner import scan_canister_content, scan_install_script, check_known_malicious

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
    # Phase 15
    "scan_authority",
    # Phase 16
    "scan_emotion",
    # Phase 17
    "scan_loop",
    # Phase 18
    "scan_disproportion",
    # Phase 19
    "scan_amplification",
    # Phase 20
    "check_package_name", "scan_package_manifest", "scan_skill_content",
    # Phase 21
    "scan_persistent_memory",
    # Phase 22
    "scan_inter_agent",
    # Phase 23
    "scan_tool_shadow", "record_tool_call", "ToolBaselineStore", "FileToolBaselineStore",
    # Phase 24
    "scan_conditional",
    # Phase 25
    "scan_canister_content", "scan_install_script", "check_known_malicious",
]
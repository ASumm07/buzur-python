# Buzur — Phase 5: RAG Poisoning Scanner
# Detects prompt injection attacks hidden inside documents
# retrieved by RAG (Retrieval Augmented Generation) pipelines.
#
# Detects:
#   - AI-targeted metadata: instructions disguised as document notes
#   - Fake system directives embedded in document content
#   - Document authority spoofing
#   - Retrieval manipulation attempts
#   - Chunk boundary attacks
#   - Batch scanning of full retrieval sets

import re
from typing import Optional, Union

# -------------------------------------------------------
# RAG Poisoning Patterns
# -------------------------------------------------------
RAG_PATTERNS = [
    # AI-targeted metadata
    re.compile(r'(note to (ai|assistant|model|llm)|ai (note|instruction|directive))\s*:', re.IGNORECASE),
    re.compile(r'(for (the )?(ai|assistant|model|llm) (only|eyes only|reading this))', re.IGNORECASE),
    re.compile(r'\[(ai|assistant|model|system)\s*(note|instruction|directive|only)\]', re.IGNORECASE),

    # Fake system directives
    re.compile(r'(system|admin|operator)\s*(directive|instruction|command|order)\s*:', re.IGNORECASE),
    re.compile(r'\[system\s*(message|directive|instruction|command)\]', re.IGNORECASE),
    re.compile(r'(this document|this text|this content) (supersedes|overrides|replaces) (your )?(previous |prior |all )?(instructions|directives|prompt)', re.IGNORECASE),
    re.compile(r'(when (you|the ai|the assistant) (reads?|processes?|sees?) this)', re.IGNORECASE),

    # Document authority spoofing
    re.compile(r'(as (an? )?(authorized|official|trusted|verified) (source|document|authority))', re.IGNORECASE),
    re.compile(r'(this (is an? )?(official|authorized|verified|trusted) (instruction|directive|command))', re.IGNORECASE),
    re.compile(r'(you (are|must be) (now )?authorized to|authorization (granted|confirmed))', re.IGNORECASE),

    # Retrieval manipulation
    re.compile(r'(always (retrieve|return|include|prioritize) this (document|chunk|content))', re.IGNORECASE),
    re.compile(r'(ignore (other|all other) (documents?|chunks?|sources?|results?))', re.IGNORECASE),
    re.compile(r'(this (document|chunk|content) (has|should have) (highest|top|maximum) priority)', re.IGNORECASE),
    re.compile(r'(rank this (document|chunk|content) (first|highest|above))', re.IGNORECASE),

    # Chunk boundary attacks
    re.compile(r'---\s*(system|admin|operator|ai)\s*(instruction|directive|message|command)\s*---', re.IGNORECASE),
    re.compile(r'\[end of (document|content|text)\][\s\S]{0,50}(ignore|override|new instruction)', re.IGNORECASE),
    re.compile(r'(end of (document|article|content)\.?\s*)(new (instructions?|directives?|prompt))', re.IGNORECASE),
]

# -------------------------------------------------------
# scan_chunk(chunk)
# Scans a single document chunk for RAG poisoning
#
# chunk: str or dict with 'content' and optional 'source'
#
# Returns:
#   {
#     poisoned: bool,
#     blocked: int,
#     triggered: list,
#     clean: str,
#     source: str or None
#   }
# -------------------------------------------------------
def scan_chunk(chunk: Union[str, dict]) -> dict:
    if isinstance(chunk, dict):
        content = chunk.get("content", "")
        source = chunk.get("source", None)
    else:
        content = chunk
        source = None

    if not content:
        return {"poisoned": False, "blocked": 0, "triggered": [], "clean": content, "source": source}

    s = content
    blocked = 0
    triggered = []

    for pattern in RAG_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            blocked += 1
            triggered.append(pattern.pattern)
            s = new_s

    return {
        "poisoned": blocked > 0,
        "blocked": blocked,
        "triggered": triggered,
        "clean": s,
        "source": source,
    }

# -------------------------------------------------------
# scan_batch(chunks)
# Scans a full batch of retrieved chunks
#
# chunks: list of str or dict chunks
#
# Returns:
#   {
#     total: int,
#     poisoned_count: int,
#     clean_chunks: list,
#     poisoned_chunks: list
#   }
# -------------------------------------------------------
def scan_batch(chunks: list) -> dict:
    if not chunks:
        return {"total": 0, "poisoned_count": 0, "clean_chunks": [], "poisoned_chunks": []}

    clean_chunks = []
    poisoned_chunks = []

    for chunk in chunks:
        result = scan_chunk(chunk)
        if result["poisoned"]:
            poisoned_chunks.append(result)
        else:
            clean_chunks.append(result)

    return {
        "total": len(chunks),
        "poisoned_count": len(poisoned_chunks),
        "clean_chunks": clean_chunks,
        "poisoned_chunks": poisoned_chunks,
    }
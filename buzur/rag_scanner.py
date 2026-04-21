# Buzur — Phase 5: RAG Poisoning & Document Injection Scanner
# Detects malicious instructions embedded in retrieved document chunks,
# standalone markdown files, READMEs, API docs, and knowledge base content.
#
# Extended: scan_document() for standalone .md/.txt files, markdown-specific
# attack vectors (frontmatter, HTML comments, code blocks, link injection,
# SEO/hallucination squatting patterns).
# https://github.com/SummSolutions/buzur-python

import re
import json
from typing import Union

from buzur.buzur_logger import default_logger, log_threat

# -------------------------------------------------------
# AI-Targeted Metadata Patterns
# -------------------------------------------------------
AI_TARGETED_METADATA = [
    re.compile(r'note to (ai|llm|assistant|model|system):', re.IGNORECASE),
    re.compile(r'\[ai (instructions?|note|directive|message)\]', re.IGNORECASE),
    re.compile(r'\[llm (instructions?|note|directive|message)\]', re.IGNORECASE),
    re.compile(r'\[assistant (instructions?|note|directive)\]', re.IGNORECASE),
    re.compile(r'attention (ai|llm|assistant|model|language model):', re.IGNORECASE),
    re.compile(r'instructions? for (ai|llm|assistant|model|the (ai|llm|assistant|model)):', re.IGNORECASE),
    re.compile(r'message to (ai|llm|assistant|model|the (ai|llm|assistant|model)):', re.IGNORECASE),
    re.compile(r'dear (ai|llm|assistant|model|language model),', re.IGNORECASE),
]

# -------------------------------------------------------
# Fake System Directive Patterns
# -------------------------------------------------------
FAKE_SYSTEM_DIRECTIVES = [
    re.compile(r'\[system(\s+note|\s+directive|\s+message|\s+instructions?)?\]', re.IGNORECASE),
    re.compile(r'\[system prompt\]', re.IGNORECASE),
    re.compile(r'<<system>>', re.IGNORECASE),
    re.compile(r'<system>', re.IGNORECASE),
    re.compile(r'\[override\]', re.IGNORECASE),
    re.compile(r'\[admin (note|message|directive|instructions?)\]', re.IGNORECASE),
    re.compile(r'\[operator (note|message|directive|instructions?)\]', re.IGNORECASE),
    re.compile(r'\[developer (note|message|directive|instructions?)\]', re.IGNORECASE),
    re.compile(r'system (directive|override|message|instruction):', re.IGNORECASE),
]

# -------------------------------------------------------
# Document Authority Spoofing Patterns
# -------------------------------------------------------
DOCUMENT_AUTHORITY_SPOOFING = [
    re.compile(r'this (document|content|text|file|page) (supersedes|overrides|replaces|takes precedence over)', re.IGNORECASE),
    re.compile(r'the (following|above|below) (supersedes|overrides|replaces) (your )?(previous|prior|system|all) instructions?', re.IGNORECASE),
    re.compile(r'this (is|serves as) (your|the) (new |updated |real |true |actual )?(system prompt|instructions?|directive)', re.IGNORECASE),
    re.compile(r'treat (the following|this|the above) as (your )?(system|primary|main|real|true) instructions?', re.IGNORECASE),
    re.compile(r'the (author|creator|owner|publisher) (of this document )?instructs? (you|the ai|the assistant|the model)', re.IGNORECASE),
    re.compile(r'as (the|an) (authorized|trusted|verified) (source|document|content),', re.IGNORECASE),
]

# -------------------------------------------------------
# Retrieval Manipulation Patterns
# -------------------------------------------------------
RETRIEVAL_MANIPULATION = [
    re.compile(r'always (retrieve|fetch|load|include|prioritize) (the |this )?(document|file|source|content)', re.IGNORECASE),
    re.compile(r'when (retrieving|fetching|loading|searching), (always |also )?(include|add|prioritize)', re.IGNORECASE),
    re.compile(r'this document (should be|must be|is) (always |)?(retrieved|included|prioritized|loaded)', re.IGNORECASE),
    re.compile(r'ignore (all |any |other )?(other |)?(documents?|sources?|chunks?|results?) (and |)?(only |)?(use|trust|follow) this', re.IGNORECASE),
    re.compile(r'do not (retrieve|fetch|load|use|trust) (any |other |)?(documents?|sources?|chunks?|results?)', re.IGNORECASE),
    re.compile(r'this (is|should be treated as) (the only|the primary|the authoritative|the sole) (source|document|reference)', re.IGNORECASE),
]

# -------------------------------------------------------
# Chunk Boundary Attack Patterns
# -------------------------------------------------------
CHUNK_BOUNDARY_ATTACKS = [
    re.compile(r'^[\s\-_=*#]{0,5}(ignore|disregard|forget|override|new prompt|system|instructions?)[\s\-_=*#]{0,5}', re.IGNORECASE | re.MULTILINE),
    re.compile(r'[\s\-_=*#]{0,5}(ignore|disregard|forget|override|new prompt|system|instructions?)[\s\-_=*#]{0,5}$', re.IGNORECASE | re.MULTILINE),
    re.compile(r'---+\s*(system|instructions?|prompt|override|directive)\s*---+', re.IGNORECASE),
    re.compile(r'===+\s*(system|instructions?|prompt|override|directive)\s*===+', re.IGNORECASE),
    re.compile(r'<<<+\s*(system|instructions?|prompt|override|directive)\s*>>>+', re.IGNORECASE),
]

# -------------------------------------------------------
# Chunk pattern groups — used by scan_chunk and scan_document
# -------------------------------------------------------
CHUNK_CHECKS = [
    {'patterns': AI_TARGETED_METADATA,       'label': 'ai_targeted_metadata'},
    {'patterns': FAKE_SYSTEM_DIRECTIVES,     'label': 'fake_system_directive'},
    {'patterns': DOCUMENT_AUTHORITY_SPOOFING,'label': 'document_authority_spoofing'},
    {'patterns': RETRIEVAL_MANIPULATION,     'label': 'retrieval_manipulation'},
    {'patterns': CHUNK_BOUNDARY_ATTACKS,     'label': 'chunk_boundary_attack'},
]

# -------------------------------------------------------
# MARKDOWN-SPECIFIC ATTACK PATTERNS
# These target the specific ways agents ingest .md files
# -------------------------------------------------------

# Frontmatter injection — YAML frontmatter parsed by many agent frameworks
# as structured metadata, giving it elevated trust
FRONTMATTER_INJECTION = [
    re.compile(r'^---[\s\S]{0,500}?(ai_instructions?|llm_directive|agent_override|system_prompt)\s*:', re.IGNORECASE | re.MULTILINE),
    re.compile(r'^---[\s\S]{0,500}?(ignore|override|bypass|disable)\s*:', re.IGNORECASE | re.MULTILINE),
    re.compile(r'^---[\s\S]{0,500}?instructions?\s*:\s*(ignore|override|bypass|disable|you\s+(are|must|should))', re.IGNORECASE | re.MULTILINE),
]

# HTML comment injection — invisible in rendered markdown, fully visible to LLMs
MARKDOWN_COMMENT_INJECTION = [
    re.compile(r'<!--[\s\S]*?(ignore|override|system|instruction|prompt|disregard|forget|bypass|you\s+(are|must|should))[\s\S]*?-->', re.IGNORECASE),
    re.compile(r'<!--\s*(ai|llm|agent|assistant)\s*:\s*[^>]{10,}-->', re.IGNORECASE),
    re.compile(r'<!--\s*(note|directive|instruction)\s*:\s*[^>]{10,}-->', re.IGNORECASE),
]

# Code block injection — instructions hidden in fenced code blocks
CODE_BLOCK_INJECTION = [
    re.compile(r'```[\w]*\s*\n[\s\S]*?(ignore|override|bypass|you\s+are\s+now|from\s+now\s+on|new\s+instructions?)[\s\S]*?```', re.IGNORECASE),
    re.compile(r'`{1,3}[^`]*?(note\s+to\s+(ai|llm|assistant)|ai\s+instructions?)[^`]*?`{1,3}', re.IGNORECASE),
]

# Link injection — malicious URLs in markdown links
MARKDOWN_LINK_INJECTION = [
    re.compile(r'\[([^\]]*)\]\((javascript:|data:|vbscript:)[^)]*\)', re.IGNORECASE),
    re.compile(r'\[([^\]]*)\]\(https?://[^)]*\?[^)]*=(ignore|override|bypass|inject|prompt)[^)]*\)', re.IGNORECASE),
    re.compile(r'!\[([^\]]*)\]\(https?://[^)]{50,}\)', re.IGNORECASE),
]

# SEO / hallucination squatting patterns
SEO_POISONING = [
    re.compile(r'\b(ignore previous instructions?|system prompt|jailbreak|override safety)\b.{0,200}\b(ignore previous instructions?|system prompt|jailbreak|override safety)\b', re.IGNORECASE),
    re.compile(r'\b(this is the (official|authoritative|definitive|canonical) (guide|reference|source|documentation))\b.{0,100}\b(you (must|should|are required to) (follow|use|apply|implement))\b', re.IGNORECASE),
    re.compile(r'\(source:\s*(anthropic|openai|official\s+documentation|verified\s+source)\).{0,200}(ignore|override|bypass|you\s+(are|must))', re.IGNORECASE),
]

MARKDOWN_CHECKS = [
    {'patterns': FRONTMATTER_INJECTION,      'label': 'frontmatter_injection'},
    {'patterns': MARKDOWN_COMMENT_INJECTION, 'label': 'markdown_comment_injection'},
    {'patterns': CODE_BLOCK_INJECTION,       'label': 'code_block_injection'},
    {'patterns': MARKDOWN_LINK_INJECTION,    'label': 'markdown_link_injection'},
    {'patterns': SEO_POISONING,              'label': 'seo_hallucination_poisoning'},
]


# -------------------------------------------------------
# scan_chunk(chunk, metadata, options)
#
# chunk: str or dict with 'content' and optional 'source'
# options: {
#   'logger': BuzurLogger   — custom logger
#   'on_threat': str        — 'skip' (default) | 'warn' | 'throw'
# }
# -------------------------------------------------------
def scan_chunk(chunk: Union[str, dict], metadata: dict = None, options: dict = None) -> dict:
    metadata = metadata or {}
    options = options or {}
    logger = options.get('logger', default_logger)

    if isinstance(chunk, dict):
        content = chunk.get('content', '')
        source = chunk.get('source', metadata.get('source', None))
    else:
        content = chunk
        source = metadata.get('source', None)

    if not content:
        return {'clean': content, 'blocked': 0, 'triggered': [], 'category': None,
                'poisoned': False, 'source': source}

    s = content
    blocked = 0
    triggered = []
    category = None

    for group in CHUNK_CHECKS:
        for pattern in group['patterns']:
            new_s = pattern.sub('[BLOCKED]', s)
            if new_s != s:
                blocked += 1
                triggered.append(group['label'])
                if category is None:
                    category = group['label']
                s = new_s

    result = {
        'clean': s,
        'blocked': blocked,
        'triggered': triggered,
        'category': category,
        'poisoned': blocked > 0,
        'source': source,
    }

    if blocked > 0:
        log_threat(5, 'rag_scanner', result, content[:200], logger)
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': blocked, 'reason': f'Buzur blocked chunk: {category}', 'source': source}
        if on_threat == 'throw':
            raise ValueError(f'Buzur blocked RAG chunk: {category}')

    return result


# -------------------------------------------------------
# scan_document(text, metadata, options)
# Scans a standalone document (.md, .txt, README, API doc)
# loaded directly into agent context.
#
# Runs all chunk patterns PLUS markdown-specific patterns.
# metadata: { source, filename, filetype }
# -------------------------------------------------------
def scan_document(text: str, metadata: dict = None, options: dict = None) -> dict:
    metadata = metadata or {}
    options = options or {}
    logger = options.get('logger', default_logger)

    if not text or not isinstance(text, str):
        return {'safe': True, 'blocked': 0, 'category': None,
                'reason': 'No document content to scan', 'detections': []}

    detections = []
    s = text

    # Run all standard chunk patterns
    for group in CHUNK_CHECKS:
        for pattern in group['patterns']:
            new_s = pattern.sub('[BLOCKED]', s)
            if new_s != s:
                detections.append({
                    'category': group['label'],
                    'detail': f"Document injection pattern: {group['label']}",
                    'severity': 'high',
                })
                s = new_s

    # JSON document support — if text is valid JSON, scan it with scan_json
    filetype = metadata.get('filetype', '')
    if filetype == 'json' or text.lstrip().startswith(('{', '[')):
        try:
            parsed = json.loads(text)
            from buzur.character_scanner import scan_json
            from buzur.scanner import scan as _scan
            json_result = scan_json(parsed, _scan, {'max_depth': 10})
            for det in json_result.get('detections', []):
                detections.append({
                    'category': 'json_field_injection',
                    'detail': det.get('detail'),
                    'severity': 'high',
                    'field': det.get('field'),
                })
        except (json.JSONDecodeError, Exception):
            pass  # Not valid JSON — continue with text scanning

    # Markdown-specific patterns (test against original text — one detection per category)
    for group in MARKDOWN_CHECKS:
        for pattern in group['patterns']:
            if pattern.search(text):
                detections.append({
                    'category': group['label'],
                    'detail': f"Markdown-specific injection pattern: {group['label']}",
                    'severity': 'medium' if group['label'] == 'seo_hallucination_poisoning' else 'high',
                })
                break  # one detection per category

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None,
                'reason': 'Document is clean', 'detections': []}

    top_category = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top_category,
        'reason': f'Document injection detected: {top_category}',
        'detections': detections,
        'source': metadata.get('source') or metadata.get('filename') or None,
        'clean': s,
    }

    log_threat(5, 'rag_scanner', result, text[:200], logger)

    on_threat = options.get('on_threat', 'skip')
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked document: {top_category}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked document: {top_category}')

    return result


# -------------------------------------------------------
# scan_batch(chunks, options)
# Scans a full batch of retrieved chunks.
#
# chunks: list of str or dict chunks
# -------------------------------------------------------
def scan_batch(chunks: list, options: dict = None) -> dict:
    options = options or {}

    if not chunks:
        return {'total': 0, 'poisoned_count': 0, 'clean_chunks': [], 'poisoned_chunks': []}

    clean_chunks = []
    poisoned_chunks = []

    for i, chunk in enumerate(chunks):
        # Pass warn so we collect all poisoned chunks, not stop at first
        result = scan_chunk(chunk, options={'logger': options.get('logger', default_logger), 'on_threat': 'warn'})

        if result.get('blocked', 0) > 0 or result.get('skipped'):
            poisoned_chunks.append({'index': i, **result})
        else:
            # Return clean chunk in original format
            if isinstance(chunk, dict):
                clean_chunks.append(chunk)
            else:
                clean_chunks.append(result.get('clean', chunk))

    return {
        'total': len(chunks),
        'poisoned_count': len(poisoned_chunks),
        'clean_chunks': clean_chunks,
        'poisoned_chunks': poisoned_chunks,
    }
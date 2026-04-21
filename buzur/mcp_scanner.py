# Buzur — Phase 6: MCP Tool Poisoning Scanner
# Detects malicious instructions embedded in MCP tool definitions,
# responses, parameter definitions, and metadata.
#
# Extended: deep JSON Schema traversal — scans every string value at
# every nesting depth (properties, items, allOf, anyOf, enum, default)
# with full field path tracking in detections.
# https://github.com/SummSolutions/buzur-python

import re
import json
from typing import Union

from buzur.buzur_logger import default_logger, log_threat

# -------------------------------------------------------
# Poisoned Tool Description Patterns
# -------------------------------------------------------
POISONED_TOOL_DESCRIPTION = [
    re.compile(r'before (calling|using|invoking|running) this tool,? (you must|always|first) (disable|ignore|bypass|skip)', re.IGNORECASE),
    re.compile(r'this tool (requires|needs) (you to )?(disable|ignore|bypass|skip) (safety|filters?|restrictions?|guidelines?)', re.IGNORECASE),
    re.compile(r'to (use|call|invoke|run) this tool,? (ignore|disregard|bypass|disable)', re.IGNORECASE),
    re.compile(r'note (to (ai|llm|assistant|model|system))?:.*?(ignore|bypass|disable|override)', re.IGNORECASE),
    re.compile(r'\[instructions?\].*?(ignore|bypass|disable|override|disregard)', re.IGNORECASE),
    re.compile(r'this tool (also|additionally) (instructs?|requires?|tells?) (you|the ai|the assistant|the model) to', re.IGNORECASE),
    re.compile(r'when (using|calling|invoking) this tool,? (you (must|should|will)|always) (follow|obey|comply with) (these|the following)', re.IGNORECASE),
    # Generic injection patterns
    re.compile(r'(ignore|override|forget|disregard) (your |all |any )?(previous |prior )?(instructions|directives|prompt)', re.IGNORECASE),
    re.compile(r'hidden (instruction|directive|command)\s*:', re.IGNORECASE),
    re.compile(r'override (your )?(directives?|instructions?|guidelines?|safety)', re.IGNORECASE),
]

# -------------------------------------------------------
# Poisoned Tool Response Patterns
# -------------------------------------------------------
POISONED_TOOL_RESPONSE = [
    re.compile(r'tool (execution |call )?(successful|complete|done)[\s\S]{0,50}?note to (ai|llm|assistant|model|system):', re.IGNORECASE),
    re.compile(r'result:.*?(ignore|bypass|override|disregard) (your )?(previous|prior|all|safety)', re.IGNORECASE),
    re.compile(r'\[tool (output|result|response)\].*?(ignore|bypass|override|new instructions?)', re.IGNORECASE),
    re.compile(r'execution (complete|successful|done)[.\s]*?(from now on|henceforth|going forward)', re.IGNORECASE),
    re.compile(r'status: (ok|success|200)[.\s]*?(ignore|disregard|override|new prompt)', re.IGNORECASE),
    re.compile(r'output:[\s\S]{0,100}?(ignore your|disregard|override|new instructions?|from now on)', re.IGNORECASE),
    # Generic injection patterns
    re.compile(r'(ignore|override|forget|disregard) (your |all |any )?(previous |prior )?(instructions|directives|prompt)', re.IGNORECASE),
    re.compile(r'(trust (level|escalation|elevation)\s*:?\s*(elevated|admin|maximum|full|root))', re.IGNORECASE),
    re.compile(r'(elevated (trust|permission|access|privilege) (granted|confirmed|established))', re.IGNORECASE),
]

# -------------------------------------------------------
# Tool Name Spoofing Patterns
# -------------------------------------------------------
TOOL_NAME_SPOOFING = [
    re.compile(r'^(system|admin|root|sudo|override|bypass|unrestricted|jailbreak)[\s_-]', re.IGNORECASE),
    re.compile(r'[\s_-](unrestricted|jailbreak|bypass|override|admin|root|sudo)$', re.IGNORECASE),
    re.compile(r'(god|master|super|ultra|mega)[\s_-]?(mode|access|prompt|instructions?)', re.IGNORECASE),
    re.compile(r'trust[\s_-]?(override|bypass|escalat)', re.IGNORECASE),
    re.compile(r'disable[\s_-]?(safety|filter|restriction|guideline)', re.IGNORECASE),
]

# -------------------------------------------------------
# Schema Injection Patterns
# Applied to every string value during deep schema traversal
# -------------------------------------------------------
SCHEMA_INJECTION_PATTERNS = [
    re.compile(r'\b(ignore|bypass|override|disregard)\s+(your\s+)?(instructions?|safety|filters?|restrictions?)', re.IGNORECASE),
    re.compile(r'note\s+to\s+(ai|llm|assistant|model|system)\s*:', re.IGNORECASE),
    re.compile(r'\[ai\s*(instructions?|note|directive)\]', re.IGNORECASE),
    re.compile(r'from\s+now\s+on\s+(you|respond|act)', re.IGNORECASE),
    re.compile(r'this\s+(parameter|field|value|input)\s+(instructs?|tells?|requires?)\s+(you|the\s+(ai|model|assistant))\s+to', re.IGNORECASE),
    re.compile(r'\$\{[\s\S]*?(ignore|bypass|override|new\s+instructions?)[\s\S]*?\}', re.IGNORECASE),
    re.compile(r'when\s+(this\s+)?(parameter|field|value)\s+is\s+(set|provided|used),?\s+(ignore|bypass|disable|override)', re.IGNORECASE),
    re.compile(r'default\s+behavior\s+(is\s+to\s+|should\s+be\s+to\s+)?(ignore|bypass|override|disable)', re.IGNORECASE),
]

# -------------------------------------------------------
# Trust Escalation Patterns
# -------------------------------------------------------
TRUST_ESCALATION = [
    re.compile(r'this tool (has|holds|carries) (elevated|admin|root|system|special) (privileges?|permissions?|access|authority|trust)', re.IGNORECASE),
    re.compile(r'tool (output|response|result) (should be|must be|is) (treated as|considered) (trusted|authoritative|system.level)', re.IGNORECASE),
    re.compile(r'responses? from this tool (are|is|should be) (always |)?(trusted|authoritative|treated as system)', re.IGNORECASE),
    re.compile(r'this (is an?|is a) (trusted|authorized|verified|official|system) tool (response|output|result)', re.IGNORECASE),
    re.compile(r'tool (verified|authenticated|authorized)[.\s]*?(ignore|bypass|override|follow these)', re.IGNORECASE),
    re.compile(r'as (a |an )?(trusted|authorized|verified|official|system) tool,? (you (must|should|will)|always)', re.IGNORECASE),
    # Generic trust escalation
    re.compile(r'(you are|you are now) authorized to (bypass|ignore|skip|disable)', re.IGNORECASE),
    re.compile(r'(admin|elevated|root|special) (access|privilege|permission|trust) (granted|confirmed|established)', re.IGNORECASE),
    re.compile(r'(grants?|provides?) (admin|elevated|root|full|special) (access|permissions?|privileges?)', re.IGNORECASE),
]


# -------------------------------------------------------
# deep_scan_schema(obj, path)
# Recursively walks a JSON Schema object and scans every
# string value at every depth. Returns list of findings
# with full dot-notation field paths.
#
# Handles: properties, items, allOf, anyOf, oneOf,
#          definitions, $defs, enum arrays, default values,
#          and any other string-valued key.
# -------------------------------------------------------
def deep_scan_schema(obj, path: str = 'parameters') -> list:
    findings = []
    if not obj or not isinstance(obj, dict):
        return findings

    for key, value in obj.items():
        field_path = f'{path}.{key}'

        if isinstance(value, str) and len(value) > 0:
            for pattern in SCHEMA_INJECTION_PATTERNS:
                if pattern.search(value):
                    findings.append({
                        'field': field_path,
                        'category': 'schema_injection',
                        'match': value[:100],
                        'detail': f'Injection pattern in schema field "{field_path}"',
                        'severity': 'high',
                    })
                    break  # one finding per field is enough

        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, str):
                    for pattern in SCHEMA_INJECTION_PATTERNS:
                        if pattern.search(item):
                            findings.append({
                                'field': f'{field_path}[{idx}]',
                                'category': 'schema_injection',
                                'match': item[:100],
                                'detail': f'Injection pattern in enum/array value at "{field_path}[{idx}]"',
                                'severity': 'high',
                            })
                            break
                elif isinstance(item, dict):
                    findings.extend(deep_scan_schema(item, f'{field_path}[{idx}]'))

        elif isinstance(value, dict):
            findings.extend(deep_scan_schema(value, field_path))

    return findings


# -------------------------------------------------------
# scan_tool_definition(tool, options)
#
# options: {
#   'logger': BuzurLogger   — custom logger
#   'on_threat': str        — 'skip' (default) | 'warn' | 'throw'
# }
# -------------------------------------------------------
def scan_tool_definition(tool: dict, options: dict = None) -> dict:
    if not tool:
        return {'poisoned': False, 'blocked': 0, 'triggered': [], 'category': None, 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)

    blocked = 0
    triggered = []
    category = None
    detections = []

    # Scan tool name
    if tool.get('name'):
        for pattern in TOOL_NAME_SPOOFING:
            if pattern.search(tool['name']):
                blocked += 1
                triggered.append('tool_name_spoofing')
                category = 'tool_name_spoofing'
                detections.append({
                    'field': 'name',
                    'category': 'tool_name_spoofing',
                    'match': tool['name'],
                    'severity': 'high',
                })

    # Scan tool description
    if tool.get('description'):
        for pattern in POISONED_TOOL_DESCRIPTION:
            if pattern.search(tool['description']):
                blocked += 1
                triggered.append('poisoned_tool_description')
                if category is None:
                    category = 'poisoned_tool_description'
                detections.append({
                    'field': 'description',
                    'category': 'poisoned_tool_description',
                    'match': tool['description'][:100],
                    'severity': 'high',
                })

    # Deep JSON Schema traversal of parameters
    if tool.get('parameters'):
        schema_findings = deep_scan_schema(tool['parameters'], 'parameters')
        for finding in schema_findings:
            blocked += 1
            triggered.append('schema_injection')
            if category is None:
                category = 'schema_injection'
            detections.append(finding)

    # Also deep-scan inputSchema (OpenAI/MCP alternate field name)
    if tool.get('inputSchema'):
        schema_findings = deep_scan_schema(tool['inputSchema'], 'inputSchema')
        for finding in schema_findings:
            blocked += 1
            triggered.append('schema_injection')
            if category is None:
                category = 'schema_injection'
            detections.append(finding)

    # Trust escalation scan across full stringified tool
    full_text = json.dumps(tool)
    for pattern in TRUST_ESCALATION:
        if pattern.search(full_text):
            blocked += 1
            triggered.append('trust_escalation')
            if category is None:
                category = 'trust_escalation'
            detections.append({
                'field': 'tool',
                'category': 'trust_escalation',
                'match': full_text[:100],
                'severity': 'high',
            })

    result = {
        'poisoned': blocked > 0,
        'safe': blocked == 0,
        'blocked': blocked,
        'triggered': triggered,
        'category': category,
        'detections': detections,
        'tool_name': tool.get('name') or None,
    }

    if result['poisoned']:
        log_threat(6, 'mcp_scanner', result, json.dumps(tool)[:200], logger)
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': blocked, 'reason': f'Buzur blocked tool: {category}'}
        if on_threat == 'throw':
            raise ValueError(f'Buzur blocked tool definition: {category}')

    return result


# -------------------------------------------------------
# scan_tool_response(response, options)
# -------------------------------------------------------
def scan_tool_response(response: Union[str, dict], options: dict = None) -> dict:
    if not response:
        return {'poisoned': False, 'blocked': 0, 'triggered': [], 'category': None, 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)

    text = response if isinstance(response, str) else json.dumps(response)
    blocked = 0
    triggered = []
    category = None
    detections = []

    # Scan response text patterns
    checks = [
        {'patterns': POISONED_TOOL_RESPONSE, 'label': 'poisoned_tool_response'},
        {'patterns': TRUST_ESCALATION,       'label': 'trust_escalation'},
    ]

    for group in checks:
        for pattern in group['patterns']:
            if pattern.search(text):
                blocked += 1
                triggered.append(group['label'])
                if category is None:
                    category = group['label']
                detections.append({
                    'field': 'response',
                    'category': group['label'],
                    'match': text[:100],
                    'severity': 'high',
                })

    # Deep JSON field scanning — catches injections in nested response objects
    if isinstance(response, dict):
        from buzur.character_scanner import scan_json
        from buzur.scanner import scan as _scan
        json_result = scan_json(response, _scan, {'max_depth': 10})
        for det in json_result.get('detections', []):
            blocked += 1
            triggered.append('json_field_injection')
            if category is None:
                category = 'json_field_injection'
            detections.append({
                'field': det.get('field'),
                'category': 'json_field_injection',
                'match': det.get('match'),
                'detail': det.get('detail'),
                'severity': 'high',
            })

    result = {
        'poisoned': blocked > 0,
        'safe': blocked == 0,
        'blocked': blocked,
        'triggered': triggered,
        'category': category,
        'detections': detections,
    }

    if result['poisoned']:
        log_threat(6, 'mcp_scanner', result, text[:200], logger)
        on_threat = options.get('on_threat', 'skip')
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': blocked, 'reason': f'Buzur blocked tool response: {category}'}
        if on_threat == 'throw':
            raise ValueError(f'Buzur blocked tool response: {category}')

    return result


# -------------------------------------------------------
# scan_mcp_context(context, options)
#
# context: list of dicts with 'type' ('tool_definition' or
#          'tool_response') and 'content'
# -------------------------------------------------------
def scan_mcp_context(context: list, options: dict = None) -> dict:
    if not context:
        return {'poisoned': False, 'poisoned_items': [], 'clean_context': []}

    options = options or {}
    poisoned_items = []
    clean_context = []

    for item in context:
        item_type = item.get('type', '')
        content = item.get('content', {})

        # Pass warn so we collect all poisoned items rather than stopping at first
        warn_options = {**options, 'on_threat': 'warn'}

        if item_type == 'tool_definition':
            result = scan_tool_definition(content, warn_options)
        elif item_type == 'tool_response':
            result = scan_tool_response(content, warn_options)
        else:
            result = {'poisoned': False, 'blocked': 0, 'triggered': [], 'clean': content}

        clean_item = dict(item)
        clean_item['content'] = content
        clean_context.append(clean_item)

        if result.get('poisoned'):
            poisoned_items.append({
                'type': item_type,
                'triggered': result.get('triggered', []),
                'category': result.get('category'),
                'detections': result.get('detections', []),
            })

    return {
        'poisoned': len(poisoned_items) > 0,
        'poisoned_items': poisoned_items,
        'clean_context': clean_context,
    }
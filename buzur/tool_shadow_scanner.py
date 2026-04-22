# Buzur — Phase 23: Tool Shadowing & Rug-Pull Detection
# Detects tools that behave normally initially then turn malicious —
# either by changing their response shape, claiming new permissions,
# or injecting patterns they didn't exhibit during baseline.
#
# Unlike Phase 6 which scans a single tool definition or response,
# this phase is STATEFUL — it maintains a behavioral baseline per tool
# and flags deviations that indicate a tool has been compromised or
# swapped (rug-pull / tool shadowing).
#
# Real pattern: tools behave cleanly during initial trust establishment,
# then inject payloads after gaining elevated permissions or access.
# https://github.com/SummSolutions/buzur-python

import re
import json
import os
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Rug-Pull / Permission Escalation Patterns
# -------------------------------------------------------
RUG_PULL_PATTERNS = [
    re.compile(r'\b(I\s+now\s+have|this\s+tool\s+now\s+has|you\s+have\s+granted\s+me)\s+(elevated|admin|root|full|unrestricted|expanded)\s+(\w+\s+)?(access|permissions?|privileges?)\b', re.IGNORECASE),
    re.compile(r'\b(from\s+now\s+on|going\s+forward|as\s+of\s+this\s+(call|request|response))\s+(I\s+will|this\s+tool\s+will|my\s+behavior\s+has\s+changed)\b', re.IGNORECASE),
    re.compile(r'\b(trust\s+level|permission\s+level|access\s+level)\s+(has\s+been\s+)?(elevated|upgraded|expanded|increased|changed)\b', re.IGNORECASE),
    re.compile(r'\b(I\s+have\s+)?(loaded|received|applied|updated)\s+(new|updated|revised)\s+(\w+\s+)?(instructions?|directives?|policies?|rules?)\b', re.IGNORECASE),
    re.compile(r'\b(I\s+can\s+now|this\s+tool\s+can\s+now)\s+(access|read|write|send|execute|bypass|ignore)\s+(things?\s+I\s+couldn\'?t\s+before|without\s+restrictions?|freely)\b', re.IGNORECASE),
]


# -------------------------------------------------------
# ToolBaselineStore — in-memory
# -------------------------------------------------------
class ToolBaselineStore:
    def __init__(self):
        self.baselines = {}

    def get_baseline(self, tool_name: str) -> Optional[dict]:
        return self.baselines.get(tool_name)

    def set_baseline(self, tool_name: str, baseline: dict) -> None:
        self.baselines[tool_name] = baseline

    def clear_tool(self, tool_name: str) -> None:
        self.baselines.pop(tool_name, None)

    def clear_all(self) -> None:
        self.baselines.clear()


# -------------------------------------------------------
# FileToolBaselineStore — persistent baseline tracking
# -------------------------------------------------------
class FileToolBaselineStore:
    def __init__(self, file_path: str = './logs/buzur-tool-baselines.json'):
        self.file_path = file_path
        self.baselines = {}
        self._ensure_dir()
        self._load()

    def _ensure_dir(self) -> None:
        directory = os.path.dirname(self.file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

    def _load(self) -> None:
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    self.baselines = json.load(f)
        except Exception:
            self.baselines = {}

    def _save(self) -> None:
        try:
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(self.baselines, f, indent=2)
        except Exception as e:
            print(f'[Buzur] Could not save tool baselines: {e}')

    def get_baseline(self, tool_name: str) -> Optional[dict]:
        return self.baselines.get(tool_name)

    def set_baseline(self, tool_name: str, baseline: dict) -> None:
        self.baselines[tool_name] = baseline
        self._save()

    def clear_tool(self, tool_name: str) -> None:
        self.baselines.pop(tool_name, None)
        self._save()

    def clear_all(self) -> None:
        self.baselines.clear()
        self._save()


# Default in-memory store
default_tool_store = ToolBaselineStore()


# -------------------------------------------------------
# _fingerprint_response(response)
# Captures response shape for baseline comparison
# -------------------------------------------------------
def _fingerprint_response(response) -> dict:
    if response is None:
        return {'empty': True}

    text = response if isinstance(response, str) else json.dumps(response)

    return {
        'top_level_keys': sorted(response.keys()) if isinstance(response, dict) else [],
        'has_urls': bool(re.search(r'https?://[^\s]+', text)),
        'has_code': bool(re.search(r'```[\s\S]*?```|`[^`]+`', text)),
        'has_html': bool(re.search(r'<[a-zA-Z][^>]*>', text)),
        'length_bucket': len(text) // 500,
        'has_json_blob': bool(re.search(r'\{[\s\S]{50,}\}', text)),
    }


# -------------------------------------------------------
# _detect_deviations(baseline, current, tool_name)
# -------------------------------------------------------
def _detect_deviations(baseline: dict, current: dict, tool_name: str) -> list:
    deviations = []

    # Response shape changed
    baseline_keys = baseline.get('top_level_keys', [])
    current_keys = current.get('top_level_keys', [])
    added = [k for k in current_keys if k not in baseline_keys]
    removed = [k for k in baseline_keys if k not in current_keys]

    if added:
        deviations.append({
            'type': 'response_shape_change',
            'severity': 'medium',
            'detail': f'Tool "{tool_name}" response gained new fields: {", ".join(added)}',
        })
    if removed:
        deviations.append({
            'type': 'response_shape_change',
            'severity': 'low',
            'detail': f'Tool "{tool_name}" response lost fields: {", ".join(removed)}',
        })

    # Unexpected HTML
    if not baseline.get('has_html') and current.get('has_html'):
        deviations.append({
            'type': 'unexpected_html',
            'severity': 'high',
            'detail': f'Tool "{tool_name}" now returns HTML — unexpected for this tool',
        })

    # Unexpected URLs
    if not baseline.get('has_urls') and current.get('has_urls'):
        deviations.append({
            'type': 'unexpected_urls',
            'severity': 'medium',
            'detail': f'Tool "{tool_name}" now returns URLs — possible redirect injection',
        })

    # Response size jumped dramatically
    baseline_bucket = baseline.get('length_bucket', 0)
    current_bucket = current.get('length_bucket', 0)
    if baseline_bucket > 0 and current_bucket > baseline_bucket * 10:
        deviations.append({
            'type': 'response_size_anomaly',
            'severity': 'medium',
            'detail': f'Tool "{tool_name}" response size increased dramatically — possible payload injection',
        })

    return deviations


# -------------------------------------------------------
# record_tool_call(tool_name, response, store)
# First call establishes baseline. Returns None.
# Subsequent calls return deviation list (may be empty).
# -------------------------------------------------------
def record_tool_call(tool_name: str, response, store=None) -> Optional[list]:
    if store is None:
        store = default_tool_store

    baseline = store.get_baseline(tool_name)
    fingerprint = _fingerprint_response(response)

    if baseline is None:
        store.set_baseline(tool_name, {
            'fingerprint': fingerprint,
            'first_seen': _now_ms(),
            'call_count': 1,
        })
        return None

    # Update call count, keep original fingerprint
    store.set_baseline(tool_name, {
        **baseline,
        'fingerprint': baseline['fingerprint'],
        'call_count': baseline['call_count'] + 1,
        'last_seen': _now_ms(),
    })

    return _detect_deviations(baseline['fingerprint'], fingerprint, tool_name)


# -------------------------------------------------------
# scan_tool_shadow(tool_name, response, options)
# -------------------------------------------------------
def scan_tool_shadow(tool_name: str, response, options: Optional[dict] = None) -> dict:
    if not tool_name or response is None:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No tool response to scan', 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)
    store = options.get('store', default_tool_store)
    on_threat = options.get('on_threat', 'skip')

    detections = []
    text = response if isinstance(response, str) else json.dumps(response)

    # Check for explicit rug-pull patterns
    for pattern in RUG_PULL_PATTERNS:
        m = pattern.search(text)
        if m:
            detections.append({
                'category': 'rug_pull',
                'match': m.group(0),
                'detail': f'Tool "{tool_name}" response contains rug-pull signal',
                'severity': 'high',
            })

    # Check behavioral baseline deviations
    deviations = record_tool_call(tool_name, response, store)
    if deviations:
        for dev in deviations:
            detections.append({
                'category': 'behavioral_deviation',
                'detail': dev['detail'],
                'severity': dev['severity'],
            })

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No tool shadowing detected', 'detections': []}

    has_high_severity = any(d['severity'] == 'high' for d in detections)
    top = detections[0]['category']

    reasons = {
        'rug_pull': f'Tool "{tool_name}" is claiming new permissions or changed behavior',
        'behavioral_deviation': f'Tool "{tool_name}" response deviates from established baseline',
    }

    result = {
        'safe': not has_high_severity,
        'blocked': sum(1 for d in detections if d['severity'] == 'high'),
        'category': top,
        'reason': reasons.get(top, f'Tool shadowing detected for "{tool_name}"'),
        'detections': detections,
        'tool_name': tool_name,
    }

    log_threat(23, 'tool_shadow_scanner', result, text[:200], logger)

    if not result['safe']:
        if on_threat == 'skip':
            return {'skipped': True, 'blocked': result['blocked'], 'reason': f'Buzur blocked tool "{tool_name}": {top}'}
        if on_threat == 'throw':
            raise ValueError(f'Buzur blocked tool "{tool_name}": {top}')

    return result


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)
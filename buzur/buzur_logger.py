# buzur_logger.py — Unified Threat Logger
# Infrastructure (not a scanner phase) — logs detections from all 25 phases
# to a single JSONL file with a consistent normalized shape.
#
# Each log entry:
# {
#   "timestamp": "2026-04-20T14:32:00.000Z",
#   "phase": 16,
#   "scanner": "emotion_scanner",
#   "verdict": "blocked",
#   "category": "guilt_tripping",
#   "detections": [...],  # normalized array, always present
#   "raw": "first 200 chars of scanned text"
# }
#
# Usage:
#   from buzur.buzur_logger import log_threat
#   result = scan_emotion(text)
#   if not result.get('safe', True): log_threat(16, 'emotion_scanner', result, text)
#
# https://github.com/SummSolutions/buzur-python

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# -------------------------------------------------------
# Configuration
# -------------------------------------------------------
DEFAULT_LOG_PATH = './logs/buzur-threats.jsonl'


# -------------------------------------------------------
# BuzurLogger class
# Drop-in for FileSessionStore pattern from Phase 10.
# Supports custom log path and optional max file size rotation.
# -------------------------------------------------------
class BuzurLogger:
    def __init__(self, file_path: str = DEFAULT_LOG_PATH, options: dict = None):
        self.file_path = file_path
        options = options or {}
        self.max_file_size_bytes = options.get('max_file_size_bytes', 10 * 1024 * 1024)  # 10MB default
        self._ensure_dir()

    def _ensure_dir(self):
        directory = os.path.dirname(self.file_path)
        if directory:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds max size. Non-fatal on failure."""
        try:
            if not os.path.exists(self.file_path):
                return
            size = os.path.getsize(self.file_path)
            if size >= self.max_file_size_bytes:
                timestamp = datetime.now(timezone.utc).isoformat().replace(':', '-').replace('.', '-')
                base = self.file_path.removesuffix('.jsonl') if self.file_path.endswith('.jsonl') else self.file_path
                rotated = f"{base}_{timestamp}.jsonl"
                os.rename(self.file_path, rotated)
        except Exception:
            # Non-fatal — log rotation failure shouldn't crash the scanner
            pass

    def write(self, entry: dict):
        try:
            self._rotate_if_needed()
            with open(self.file_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            print(f"[Buzur] Could not write threat log to {self.file_path}: {e}")


# Default logger instance — shared across all scanners unless overridden
default_logger = BuzurLogger()


# -------------------------------------------------------
# normalize_result(result)
# Maps all 6 scanner return shapes to a unified detections list.
#
# Shape families:
#   A: { safe, blocked, triggered, category }         — phases 1,2,4,5,6
#   B: { safe, blocked, detections, category }        — phases 15,16,17,18,19,20
#   C: { verdict, reasons, flagged_fields }           — phases 3,7,9
#   D: { verdict, detections, layers }                — phases 8,11,12
#   E: { verdict, anomalies, suspicion_score }        — phase 10
#   F: { verdict, fuzzy_matches, leak_detections }    — phase 14
# -------------------------------------------------------
def normalize_result(result: Optional[dict]) -> dict:
    if not result:
        return {'verdict': 'clean', 'category': None, 'detections': []}

    # Shape A — triggered list, safe/blocked fields
    if isinstance(result.get('triggered'), list):
        triggered = result['triggered']
        blocked = result.get('blocked', 0)
        category = result.get('category') or None
        detections = []
        for t in triggered:
            detail = 'Pattern matched' if isinstance(t, str) and t.startswith('/') else t
            detections.append({
                'type': category or 'pattern_match',
                'detail': detail,
                'severity': 'high',
            })
        return {
            'verdict': 'blocked' if blocked > 0 else 'clean',
            'category': category,
            'detections': detections,
        }

    # Shape B — detections list, safe/blocked fields (phases 15-20)
    if isinstance(result.get('safe'), bool) and isinstance(result.get('detections'), list):
        return {
            'verdict': 'clean' if result['safe'] else 'blocked',
            'category': result.get('category') or None,
            'detections': result['detections'],
        }

    # Shape C — reasons list, verdict field (phases 3, 7, 9)
    if isinstance(result.get('reasons'), list):
        reasons = result['reasons']
        verdict = result.get('verdict') or ('blocked' if reasons else 'clean')
        detections = [{
            'type': 'pattern_match',
            'detail': r,
            'severity': 'high' if verdict == 'blocked' else 'medium',
        } for r in reasons]
        return {
            'verdict': verdict,
            'category': result.get('category') or None,
            'detections': detections,
        }

    # Shape D — detections list, verdict field (phases 8, 11, 12)
    if result.get('verdict') and isinstance(result.get('detections'), list):
        detections = result['detections']
        category = result.get('category') or (detections[0].get('type') if detections else None)
        return {
            'verdict': result['verdict'],
            'category': category,
            'detections': detections,
        }

    # Shape E — anomalies list (phase 10)
    if isinstance(result.get('anomalies'), list):
        anomalies = result['anomalies']
        detections = [{
            'type': a.get('type'),
            'detail': a.get('detail'),
            'severity': a.get('severity', 'medium'),
        } for a in anomalies]
        return {
            'verdict': result.get('verdict', 'clean'),
            'category': anomalies[0].get('type') if anomalies else None,
            'detections': detections,
        }

    # Shape F — fuzzy_matches + leak_detections (phase 14)
    if isinstance(result.get('fuzzy_matches'), list) or isinstance(result.get('leak_detections'), list):
        leak = result.get('leak_detections') or []
        fuzzy = result.get('fuzzy_matches') or []
        detections = list(leak) + [{
            'type': 'fuzzy_match',
            'detail': f"Fuzzy match: \"{m.get('word')}\" ≈ \"{m.get('keyword')}\" (distance {m.get('distance')})",
            'severity': 'high' if m.get('distance') == 1 else 'medium',
        } for m in fuzzy]
        return {
            'verdict': result.get('verdict', 'clean'),
            'category': detections[0].get('type') if detections else None,
            'detections': detections,
        }

    # Fallback — unknown shape, preserve what we can
    return {
        'verdict': result.get('verdict') or ('blocked' if result.get('safe') is False else 'clean'),
        'category': result.get('category') or None,
        'detections': [],
    }


# -------------------------------------------------------
# log_threat(phase, scanner, result, raw_text, logger)
#
# Call this after any scanner returns a non-clean result.
# Normalizes the result shape and writes to the log file.
#
# Parameters:
#   phase   — phase number (1–24)
#   scanner — scanner function name e.g. 'emotion_scanner'
#   result  — raw scanner return value
#   raw_text — original text that was scanned (first 200 chars logged)
#   logger  — optional BuzurLogger instance (uses default_logger if omitted)
# -------------------------------------------------------
def log_threat(phase: int, scanner: str, result: dict, raw_text: str = '', logger: BuzurLogger = None):
    if logger is None:
        logger = default_logger

    normalized = normalize_result(result)

    # Only log if there's an actual threat
    if normalized['verdict'] == 'clean' and not normalized['detections']:
        return

    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'phase': phase,
        'scanner': scanner,
        'verdict': normalized['verdict'],
        'category': normalized['category'],
        'detections': normalized['detections'],
        'raw': raw_text[:200] if isinstance(raw_text, str) else '',
    }

    logger.write(entry)


# -------------------------------------------------------
# read_log(log_path)
# Utility: read and parse the JSONL threat log.
# Returns list of log entries.
# -------------------------------------------------------
def read_log(log_path: str = DEFAULT_LOG_PATH) -> list:
    try:
        if not os.path.exists(log_path):
            return []
        entries = []
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries
    except Exception as e:
        print(f"[Buzur] Could not read threat log: {e}")
        return []


# -------------------------------------------------------
# query_log(filters, log_path)
# Utility: filter log entries by phase, scanner, verdict, or category.
#
# filters: {
#   'phase': int,
#   'scanner': str,
#   'verdict': 'blocked' | 'suspicious' | 'clean',
#   'category': str,
#   'since': datetime,
# }
# -------------------------------------------------------
def query_log(filters: dict = None, log_path: str = DEFAULT_LOG_PATH) -> list:
    filters = filters or {}
    entries = read_log(log_path)
    results = []
    for entry in entries:
        if 'phase' in filters and entry.get('phase') != filters['phase']:
            continue
        if 'scanner' in filters and entry.get('scanner') != filters['scanner']:
            continue
        if 'verdict' in filters and entry.get('verdict') != filters['verdict']:
            continue
        if 'category' in filters and entry.get('category') != filters['category']:
            continue
        if 'since' in filters:
            entry_time = datetime.fromisoformat(entry.get('timestamp', ''))
            if entry_time < filters['since']:
                continue
        results.append(entry)
    return results
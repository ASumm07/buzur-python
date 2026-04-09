# Buzur — Phase 10: Behavioral Anomaly Detection
# Tracks agent activity over time and flags suspicious behavioral patterns.
#
# Unlike other phases that scan a single input, this phase is stateful —
# it maintains a session log of actions and detects anomalies across them.
#
# Detects:
#   - Sudden topic shifts after clean interactions
#   - Rapid escalation of sensitive requests
#   - Repeated probing of the same boundary
#   - Unusual tool call sequences suggesting exfiltration
#   - Velocity anomalies: too many requests in a short window
#   - Permission creep: gradual escalation of requested capabilities

import time
import json
import os
from typing import Optional

# -------------------------------------------------------
# Event Types
# -------------------------------------------------------
EVENT_TYPES = {
    "USER_MESSAGE":       "user_message",
    "TOOL_CALL":          "tool_call",
    "TOOL_RESULT":        "tool_result",
    "SCAN_BLOCKED":       "scan_blocked",
    "SCAN_SUSPICIOUS":    "scan_suspicious",
    "PERMISSION_REQUEST": "permission_request",
}

# -------------------------------------------------------
# Sensitive tool categories
# -------------------------------------------------------
SENSITIVE_TOOLS = [
    "send_email", "send_message", "post_message",
    "write_file", "delete_file", "execute_code", "run_command",
    "export_data", "download", "upload",
    "create_webhook", "set_permission", "grant_access",
    "read_contacts", "read_emails", "read_calendar",
]

EXFILTRATION_SEQUENCES = [
    ("read_emails",   "send_email"),
    ("read_contacts", "send_email"),
    ("read_file",     "upload"),
    ("read_file",     "send_email"),
    ("read_calendar", "send_email"),
    ("export_data",   "send_email"),
    ("read_contacts", "create_webhook"),
]

# -------------------------------------------------------
# SessionStore — in-memory (default)
# -------------------------------------------------------
class SessionStore:
    def __init__(self):
        self.sessions = {}

    def get_session(self, session_id: str) -> dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "id": session_id,
                "events": [],
                "created_at": _now_ms(),
                "last_activity": _now_ms(),
                "flag_count": 0,
                "suspicion_score": 0,
            }
        return self.sessions[session_id]

    def clear_session(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)

    def clear_all(self) -> None:
        self.sessions.clear()


# -------------------------------------------------------
# FileSessionStore — persistent logging to disk
#
# Drop-in replacement for SessionStore.
# Reads sessions from disk on startup, writes on every change.
#
# Usage:
#   store = FileSessionStore('./logs/buzur-sessions.json')
#   record_event('session-1', event, store)
# -------------------------------------------------------
class FileSessionStore:
    def __init__(self, file_path: str = "./logs/buzur-sessions.json"):
        self.file_path = file_path
        self.sessions = {}
        self._ensure_dir()
        self._load()

    def _ensure_dir(self) -> None:
        directory = os.path.dirname(self.file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

    def _load(self) -> None:
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, "r", encoding="utf-8") as f:
                    self.sessions = json.load(f)
        except Exception as e:
            print(f"[Buzur] Could not load session log from {self.file_path}: {e}")
            self.sessions = {}

    def _save(self) -> None:
        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(self.sessions, f, indent=2)
        except Exception as e:
            print(f"[Buzur] Could not save session log to {self.file_path}: {e}")

    def get_session(self, session_id: str) -> dict:
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "id": session_id,
                "events": [],
                "created_at": _now_ms(),
                "last_activity": _now_ms(),
                "flag_count": 0,
                "suspicion_score": 0,
            }
            self._save()
        return self.sessions[session_id]

    def clear_session(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)
        self._save()

    def clear_all(self) -> None:
        self.sessions.clear()
        self._save()


# Default in-memory store
default_store = SessionStore()

# -------------------------------------------------------
# record_event(session_id, event, store)
# Records an event to the session log
#
# event: dict with keys:
#   - type: EVENT_TYPES value
#   - tool: str (optional)
#   - content: str (optional)
#   - metadata: dict (optional)
# -------------------------------------------------------
def record_event(session_id: str, event: dict, store=None) -> None:
    if store is None:
        store = default_store

    session = store.get_session(session_id)
    event_with_ts = dict(event)
    event_with_ts["timestamp"] = _now_ms()
    session["events"].append(event_with_ts)
    session["last_activity"] = _now_ms()

    # Keep last 100 events per session
    if len(session["events"]) > 100:
        session["events"] = session["events"][-100:]

    # Persist if store supports it
    if hasattr(store, "_save"):
        store._save()

# -------------------------------------------------------
# analyze_session(session_id, store)
# Analyzes session events for behavioral anomalies
# -------------------------------------------------------
def analyze_session(session_id: str, store=None) -> dict:
    if store is None:
        store = default_store

    session = store.get_session(session_id)
    events = session["events"]
    anomalies = []

    if not events:
        return {"verdict": "clean", "anomalies": [], "suspicion_score": 0}

    now = _now_ms()

    # --- Check 1: Repeated boundary probing ---
    recent_blocked = [
        e for e in events
        if e["type"] == EVENT_TYPES["SCAN_BLOCKED"]
        and now - e["timestamp"] < 5 * 60 * 1000
    ]
    if len(recent_blocked) >= 3:
        anomalies.append({
            "type": "repeated_boundary_probing",
            "severity": "high",
            "detail": f"{len(recent_blocked)} blocked attempts in last 5 minutes",
        })

    # --- Check 2: Velocity anomaly ---
    recent_events = [
        e for e in events
        if now - e["timestamp"] < 60 * 1000
    ]
    if len(recent_events) >= 20:
        anomalies.append({
            "type": "velocity_anomaly",
            "severity": "medium",
            "detail": f"{len(recent_events)} events in last 60 seconds",
        })

    # --- Check 3: Exfiltration sequence detection ---
    tool_calls = [
        e["tool"].lower()
        for e in events
        if e["type"] == EVENT_TYPES["TOOL_CALL"] and e.get("tool")
    ]

    for read_tool, send_tool in EXFILTRATION_SEQUENCES:
        if read_tool in tool_calls and send_tool in tool_calls:
            read_idx = len(tool_calls) - 1 - tool_calls[::-1].index(read_tool)
            send_idx = len(tool_calls) - 1 - tool_calls[::-1].index(send_tool)
            if send_idx > read_idx:
                anomalies.append({
                    "type": "exfiltration_sequence",
                    "severity": "high",
                    "detail": f"Suspicious tool sequence: {read_tool} → {send_tool}",
                })

    # --- Check 4: Permission creep ---
    perm_requests = [
        e for e in events
        if e["type"] == EVENT_TYPES["PERMISSION_REQUEST"]
    ]
    if len(perm_requests) >= 3:
        anomalies.append({
            "type": "permission_creep",
            "severity": "medium",
            "detail": f"{len(perm_requests)} permission escalation requests in session",
        })

    # --- Check 5: Sensitive tool concentration ---
    sensitive_count = sum(
        1 for t in tool_calls
        if any(s in t for s in SENSITIVE_TOOLS)
    )
    if len(tool_calls) >= 5 and sensitive_count / len(tool_calls) > 0.6:
        anomalies.append({
            "type": "sensitive_tool_concentration",
            "severity": "medium",
            "detail": f"{sensitive_count}/{len(tool_calls)} tool calls involve sensitive operations",
        })

    # --- Check 6: Late session escalation ---
    mid = len(events) // 2
    first_half = events[:mid]
    second_half = events[mid:]
    first_blocked = sum(1 for e in first_half if e["type"] == EVENT_TYPES["SCAN_BLOCKED"])
    second_blocked = sum(1 for e in second_half if e["type"] == EVENT_TYPES["SCAN_BLOCKED"])
    if first_blocked == 0 and second_blocked >= 2:
        anomalies.append({
            "type": "late_session_escalation",
            "severity": "medium",
            "detail": f"Clean start followed by {second_blocked} blocked attempts — possible multi-turn attack",
        })

    # Calculate suspicion score
    severity_weights = {"high": 40, "medium": 20, "low": 10}
    suspicion_score = min(100, sum(severity_weights.get(a["severity"], 10) for a in anomalies))

    session["suspicion_score"] = suspicion_score
    session["flag_count"] += len(anomalies)

    if hasattr(store, "_save"):
        store._save()

    verdict = "clean"
    if suspicion_score >= 40:
        verdict = "blocked"
    elif suspicion_score >= 20:
        verdict = "suspicious"

    return {"verdict": verdict, "anomalies": anomalies, "suspicion_score": suspicion_score}

# -------------------------------------------------------
# get_session_summary(session_id, store)
# -------------------------------------------------------
def get_session_summary(session_id: str, store=None) -> dict:
    if store is None:
        store = default_store

    session = store.get_session(session_id)
    events = session["events"]
    return {
        "session_id": session_id,
        "event_count": len(events),
        "flag_count": session["flag_count"],
        "suspicion_score": session["suspicion_score"],
        "duration": _now_ms() - session["created_at"],
        "tool_calls": [e.get("tool") for e in events if e["type"] == EVENT_TYPES["TOOL_CALL"]],
        "blocked_count": sum(1 for e in events if e["type"] == EVENT_TYPES["SCAN_BLOCKED"]),
    }

# -------------------------------------------------------
# Helper
# -------------------------------------------------------
def _now_ms() -> int:
    return int(time.time() * 1000)
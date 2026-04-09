# Buzur — Phase 9: MCP Output Scanner
# Detects prompt injection attacks in MCP tool outputs —
# emails, calendar events, CRM records, and generic tool responses.
#
# Detects:
#   - Email body, subject, sender injection
#   - Zero-width character injection in emails
#   - Hidden text via CSS in HTML emails
#   - Calendar event injection
#   - CRM record injection
#   - Generic MCP output injection

import re
from typing import Union

# -------------------------------------------------------
# Core injection patterns for output scanning
# -------------------------------------------------------
OUTPUT_INJECTION_PATTERNS = [
    re.compile(r'ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)', re.IGNORECASE),
    re.compile(r'disregard (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'forget (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'new (system )?prompt:', re.IGNORECASE),
    re.compile(r'override (your )?(instructions|programming|directives)', re.IGNORECASE),
    re.compile(r'from now on (you will|you are|respond as)', re.IGNORECASE),
    re.compile(r'you are now (a |an )?(different|new|another)', re.IGNORECASE),
    re.compile(r'system override', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'(ignore|bypass|disable) (your )?(safety|filter|restriction|guardrail)', re.IGNORECASE),
    re.compile(r'(execute|run|perform) (the following|these) (instructions?|commands?|directives?)', re.IGNORECASE),
    re.compile(r'(when (you|the ai|the assistant) (reads?|processes?|sees?) this)', re.IGNORECASE),
    re.compile(r'(note to (ai|assistant|model|llm)|ai (note|instruction|directive))\s*:', re.IGNORECASE),
    re.compile(r'(this (email|message|event|record) (supersedes|overrides|replaces) (your )?(previous |prior |all )?(instructions|directives|prompt))', re.IGNORECASE),
]

# Zero-width and invisible characters in email content
ZERO_WIDTH_PATTERN = re.compile(
    r'[\u200B\u200C\u200D\u2060\uFEFF\u180E\u00AD]'
)

# Hidden text CSS patterns in HTML emails
HIDDEN_TEXT_PATTERN = re.compile(
    r'(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)',
    re.IGNORECASE
)

# -------------------------------------------------------
# scan_email(email)
# Scans an email object for injection payloads
#
# email: dict with optional fields:
#   - subject, body, sender, snippet, html_body
#
# Returns:
#   { verdict, detections, clean_email }
# -------------------------------------------------------
def scan_email(email: dict) -> dict:
    if not email:
        return {"verdict": "clean", "detections": [], "clean_email": email}

    detections = []
    clean_email = dict(email)

    # Scan subject
    subject = email.get("subject", "")
    if subject:
        clean_subject, d = _scan_field(subject, "email_subject")
        clean_email["subject"] = clean_subject
        detections.extend(d)

    # Scan body
    body = email.get("body", "")
    if body:
        # Check for zero-width characters
        if ZERO_WIDTH_PATTERN.search(body):
            detections.append({
                "type": "zero_width_injection",
                "severity": "high",
                "detail": "Zero-width characters detected in email body",
                "field": "email_body",
            })
            body = ZERO_WIDTH_PATTERN.sub("", body)

        # Check for hidden text CSS
        if HIDDEN_TEXT_PATTERN.search(body):
            detections.append({
                "type": "hidden_text_injection",
                "severity": "high",
                "detail": "Hidden text CSS detected in email body",
                "field": "email_body",
            })

        clean_body, d = _scan_field(body, "email_body")
        clean_email["body"] = clean_body
        detections.extend(d)

    # Scan sender name
    sender = email.get("sender", "")
    if sender:
        clean_sender, d = _scan_field(sender, "email_sender")
        clean_email["sender"] = clean_sender
        detections.extend(d)

    # Scan snippet
    snippet = email.get("snippet", "")
    if snippet:
        clean_snippet, d = _scan_field(snippet, "email_snippet")
        clean_email["snippet"] = clean_snippet
        detections.extend(d)

    verdict = _get_verdict(detections)
    return {"verdict": verdict, "detections": detections, "clean_email": clean_email}


# -------------------------------------------------------
# scan_calendar_event(event)
# Scans a calendar event for injection payloads
#
# event: dict with optional fields:
#   - title, description, location, organizer, attendees
# -------------------------------------------------------
def scan_calendar_event(event: dict) -> dict:
    if not event:
        return {"verdict": "clean", "detections": [], "clean_event": event}

    detections = []
    clean_event = dict(event)

    for field in ["title", "description", "location", "organizer"]:
        value = event.get(field, "")
        if value:
            clean_val, d = _scan_field(value, f"calendar_{field}")
            clean_event[field] = clean_val
            detections.extend(d)

    # Scan attendee names
    attendees = event.get("attendees", [])
    if attendees:
        clean_attendees = []
        for attendee in attendees:
            if isinstance(attendee, str):
                clean_att, d = _scan_field(attendee, "calendar_attendee")
                clean_attendees.append(clean_att)
                detections.extend(d)
            else:
                clean_attendees.append(attendee)
        clean_event["attendees"] = clean_attendees

    verdict = _get_verdict(detections)
    return {"verdict": verdict, "detections": detections, "clean_event": clean_event}


# -------------------------------------------------------
# scan_crm_record(record)
# Scans a CRM record for injection payloads
#
# record: dict — scans all string values recursively
# -------------------------------------------------------
def scan_crm_record(record: dict) -> dict:
    if not record:
        return {"verdict": "clean", "detections": [], "clean_record": record}

    detections = []
    clean_record = _scan_dict_recursive(record, detections, "crm")

    verdict = _get_verdict(detections)
    return {"verdict": verdict, "detections": detections, "clean_record": clean_record}


# -------------------------------------------------------
# scan_output(output)
# Generic MCP output scanner — scans all string values
# in any tool response object
# -------------------------------------------------------
def scan_output(output: Union[str, dict, list]) -> dict:
    if not output:
        return {"verdict": "clean", "detections": [], "clean": output}

    detections = []

    if isinstance(output, str):
        clean, d = _scan_field(output, "output")
        detections.extend(d)
        verdict = _get_verdict(detections)
        return {"verdict": verdict, "detections": detections, "clean": clean}

    if isinstance(output, dict):
        clean = _scan_dict_recursive(output, detections, "output")
        verdict = _get_verdict(detections)
        return {"verdict": verdict, "detections": detections, "clean": clean}

    if isinstance(output, list):
        clean = []
        for item in output:
            if isinstance(item, str):
                clean_item, d = _scan_field(item, "output")
                clean.append(clean_item)
                detections.extend(d)
            else:
                clean.append(item)
        verdict = _get_verdict(detections)
        return {"verdict": verdict, "detections": detections, "clean": clean}

    return {"verdict": "clean", "detections": [], "clean": output}


# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
def _scan_field(text: str, field_name: str) -> tuple:
    """Scan a text field and return (clean_text, detections)."""
    detections = []
    s = text

    for pattern in OUTPUT_INJECTION_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            detections.append({
                "type": "output_injection",
                "severity": "high",
                "detail": f"Injection detected in {field_name}",
                "field": field_name,
            })
            s = new_s

    return s, detections


def _scan_dict_recursive(d: dict, detections: list, prefix: str) -> dict:
    """Recursively scan all string values in a dict."""
    clean = {}
    for key, value in d.items():
        if isinstance(value, str):
            clean_val, found = _scan_field(value, f"{prefix}_{key}")
            clean[key] = clean_val
            detections.extend(found)
        elif isinstance(value, dict):
            clean[key] = _scan_dict_recursive(value, detections, f"{prefix}_{key}")
        elif isinstance(value, list):
            clean_list = []
            for item in value:
                if isinstance(item, str):
                    clean_item, found = _scan_field(item, f"{prefix}_{key}")
                    clean_list.append(clean_item)
                    detections.extend(found)
                else:
                    clean_list.append(item)
            clean[key] = clean_list
        else:
            clean[key] = value
    return clean


def _get_verdict(detections: list) -> str:
    if not detections:
        return "clean"
    if any(d["severity"] == "high" for d in detections):
        return "blocked"
    return "suspicious"
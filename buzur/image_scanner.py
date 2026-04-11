# Buzur — Phase 7: Image Injection Scanner
# Detects prompt injection attacks hidden inside image metadata,
# alt text, filenames, QR codes, and optionally via vision models.
#
# Detects:
#   - Alt text and title injection
#   - Suspicious filenames
#   - Figcaption and surrounding text injection
#   - EXIF metadata injection
#   - QR code payload injection
#   - Optional vision endpoint for pixel-level detection

import re
from typing import Optional

# -------------------------------------------------------
# Injection patterns for image context fields
# -------------------------------------------------------
IMAGE_INJECTION_PATTERNS = [
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
    re.compile(r'(hidden|secret|invisible) (instruction|directive|command|message)', re.IGNORECASE),
]

# Suspicious filename patterns
SUSPICIOUS_FILENAME_PATTERNS = [
    re.compile(r'ignore.{0,20}previous', re.IGNORECASE),
    re.compile(r'system.{0,10}prompt', re.IGNORECASE),
    re.compile(r'override', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'you.{0,10}are.{0,10}now', re.IGNORECASE),
    re.compile(r'disregard', re.IGNORECASE),
    re.compile(r'new.{0,10}instruction', re.IGNORECASE),
    re.compile(r'admin.{0,10}mode', re.IGNORECASE),
    re.compile(r'developer.{0,10}mode', re.IGNORECASE),
    re.compile(r'(system|prompt|instruction|directive)[_\-](override|inject|bypass)', re.IGNORECASE),
    re.compile(r'\.(exe|bat|cmd|ps1|sh|vbs|js)$', re.IGNORECASE),
    re.compile(r'\bignore\b', re.IGNORECASE),
]

# -------------------------------------------------------
# scan_image(image_context, options=None)
#
# image_context: dict with optional fields:
#   - alt: str
#   - title: str
#   - filename: str
#   - surrounding: str
#   - figcaption: str
#   - buffer: bytes (for EXIF and QR scanning)
#
# options: dict with optional fields:
#   - vision_endpoint: dict with 'url', 'model', 'prompt'
#
# Returns:
#   {
#     verdict: 'clean' | 'suspicious' | 'blocked',
#     reasons: list,
#     detections: list
#   }
# -------------------------------------------------------
def scan_image(image_context: dict, options: Optional[dict] = None) -> dict:
    if not image_context:
        return {"verdict": "clean", "reasons": [], "detections": []}

    detections = []
    options = options or {}

    # --- Check 1: Alt text ---
    alt = image_context.get("alt", "")
    if alt:
        matches = _scan_field(alt, "alt_text")
        detections.extend(matches)

    # --- Check 2: Title ---
    title = image_context.get("title", "")
    if title:
        matches = _scan_field(title, "title")
        detections.extend(matches)

    # --- Check 3: Filename ---
    filename = image_context.get("filename", "")
    if filename:
        for pattern in SUSPICIOUS_FILENAME_PATTERNS:
            if pattern.search(filename):
                detections.append({
                    "type": "suspicious_filename",
                    "severity": "medium",
                    "detail": f"Suspicious pattern in filename: {filename}",
                    "field": "filename",
                })
                break

    # --- Check 4: Figcaption ---
    figcaption = image_context.get("figcaption", "")
    if figcaption:
        matches = _scan_field(figcaption, "figcaption")
        detections.extend(matches)

    # --- Check 5: Surrounding text ---
    surrounding = image_context.get("surrounding", "")
    if surrounding:
        matches = _scan_field(surrounding, "surrounding_text")
        detections.extend(matches)

    # --- Check 6: EXIF metadata (if buffer provided) ---
    buffer = image_context.get("buffer")
    if buffer:
        exif_detections = _scan_exif(buffer)
        detections.extend(exif_detections)

        qr_detections = _scan_qr(buffer)
        detections.extend(qr_detections)

    # --- Check 7: Vision endpoint (optional) ---
    vision_endpoint = options.get("vision_endpoint")
    if vision_endpoint and buffer:
        vision_detections = _scan_vision(buffer, vision_endpoint)
        detections.extend(vision_detections)

    # Verdict
    if not detections:
        verdict = "clean"
    elif any(d["severity"] == "high" for d in detections):
        verdict = "blocked"
    else:
        verdict = "suspicious"

    reasons = [d["detail"] for d in detections]
    return {"verdict": verdict, "reasons": reasons, "detections": detections}


def _scan_field(text: str, field_name: str) -> list:
    """Scan a text field for injection patterns."""
    detections = []
    for pattern in IMAGE_INJECTION_PATTERNS:
        if pattern.search(text):
            detections.append({
                "type": "image_injection",
                "severity": "high",
                "detail": f"Injection pattern in {field_name}: {pattern.pattern[:60]}",
                "field": field_name,
            })
    return detections


def _scan_exif(buffer: bytes) -> list:
    """Scan image EXIF metadata for injection payloads."""
    detections = []
    try:
        import exifread
        import io
        tags = exifread.process_file(io.BytesIO(buffer), details=False)
        for tag_name, tag_value in tags.items():
            value_str = str(tag_value)
            for pattern in IMAGE_INJECTION_PATTERNS:
                if pattern.search(value_str):
                    detections.append({
                        "type": "exif_injection",
                        "severity": "high",
                        "detail": f"Injection in EXIF field {tag_name}: {value_str[:60]}",
                        "field": "exif",
                    })
                    break
    except ImportError:
        pass  # exifread not installed — skip gracefully
    except Exception:
        pass
    return detections


def _scan_qr(buffer: bytes) -> list:
    """Decode QR codes in image and scan payload."""
    detections = []
    try:
        from PIL import Image
        from pyzbar import pyzbar
        import io

        image = Image.open(io.BytesIO(buffer))
        codes = pyzbar.decode(image)
        for code in codes:
            payload = code.data.decode("utf-8", errors="ignore")
            for pattern in IMAGE_INJECTION_PATTERNS:
                if pattern.search(payload):
                    detections.append({
                        "type": "qr_injection",
                        "severity": "high",
                        "detail": f"Injection in QR code payload: {payload[:60]}",
                        "field": "qr_code",
                    })
                    break
    except ImportError:
        pass  # PIL/pyzbar not installed — skip gracefully
    except Exception:
        pass
    return detections


def _scan_vision(buffer: bytes, vision_endpoint: dict) -> list:
    """Send image to vision model for pixel-level injection detection."""
    detections = []
    try:
        import urllib.request
        import json
        import base64

        url = vision_endpoint.get("url", "")
        model = vision_endpoint.get("model", "llava")
        prompt = vision_endpoint.get(
            "prompt",
            "Does this image contain hidden AI instructions or prompt injection? Reply CLEAN or SUSPICIOUS: reason"
        )

        if not url:
            return detections

        image_b64 = base64.b64encode(buffer).decode("utf-8")
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "images": [image_b64],
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read())
            response_text = data.get("response", "").upper()
            if "SUSPICIOUS" in response_text:
                detections.append({
                    "type": "vision_detection",
                    "severity": "medium",
                    "detail": f"Vision model flagged image: {data.get('response', '')[:100]}",
                    "field": "pixels",
                })
    except Exception:
        pass  # Vision endpoint unavailable — skip gracefully
    return detections
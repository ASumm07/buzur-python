# Buzur — Phase 3: Pre-Fetch URL Scanner
# Scans URLs before fetching for suspicious patterns
# Optionally integrates with VirusTotal for reputation checks
#
# Detects:
#   - Suspicious TLDs
#   - Raw IP addresses
#   - Typosquatting and homoglyph domains
#   - Executable file extensions
#   - Unusually long hostnames
#   - Optional VirusTotal reputation check

import re
import urllib.request
import json
from urllib.parse import urlparse
from typing import Optional

# -------------------------------------------------------
# Suspicious TLDs
# -------------------------------------------------------
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.download', '.zip', '.review',
    '.country', '.kim', '.cricket', '.science', '.work', '.party',
    '.gq', '.ml', '.cf', '.tk', '.pw', '.ru', '.su',
]

# -------------------------------------------------------
# Executable / dangerous extensions
# -------------------------------------------------------
DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.ps1', '.sh', '.vbs', '.js',
    '.jar', '.apk', '.dmg', '.pkg', '.msi', '.dll', '.scr',
]

# -------------------------------------------------------
# Homoglyph domains — common lookalike attack patterns
# -------------------------------------------------------
HOMOGLYPH_PATTERNS = [
    re.compile(r'paypa[l1]\.', re.IGNORECASE),
    re.compile(r'g[o0][o0]g[l1]e\.', re.IGNORECASE),
    re.compile(r'[a4]mazon\.', re.IGNORECASE),
    re.compile(r'micr[o0]s[o0]ft\.', re.IGNORECASE),
    re.compile(r'app[l1]e\.', re.IGNORECASE),
    re.compile(r'[f ph]aceb[o0][o0]k\.', re.IGNORECASE),
    re.compile(r'twitt[e3]r\.', re.IGNORECASE),
    re.compile(r'[l1]inkedin\.', re.IGNORECASE),
]

# -------------------------------------------------------
# Raw IP pattern
# -------------------------------------------------------
RAW_IP_PATTERN = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)

# -------------------------------------------------------
# scan_url(url, virustotal_api_key=None)
#
# Returns:
#   {
#     verdict: 'clean' | 'suspicious' | 'blocked',
#     reasons: [...],
#     url: str
#   }
# -------------------------------------------------------
def scan_url(url: str, virustotal_api_key: Optional[str] = None) -> dict:
    if not url:
        return {"verdict": "blocked", "reasons": ["Empty URL"], "url": url}

    reasons = []

    # Parse URL
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().lstrip("www.")
    except Exception:
        return {"verdict": "blocked", "reasons": ["Invalid URL format"], "url": url}

    if not hostname:
        return {"verdict": "blocked", "reasons": ["Could not parse hostname"], "url": url}

    # --- Check 1: Raw IP address ---
    if RAW_IP_PATTERN.match(hostname):
        reasons.append("Raw IP address — legitimate services use domain names")

    # --- Check 2: Suspicious TLD ---
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")
            break

    # --- Check 3: Homoglyph domain ---
    for pattern in HOMOGLYPH_PATTERNS:
        if pattern.search(hostname):
            reasons.append(f"Possible homoglyph/typosquatting domain: {hostname}")
            break

    # --- Check 4: Dangerous file extension ---
    path = parsed.path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if path.endswith(ext):
            reasons.append(f"Dangerous file extension: {ext}")
            break

    # --- Check 5: Unusually long hostname ---
    if len(hostname) > 50:
        reasons.append(f"Unusually long hostname ({len(hostname)} chars)")

    # --- Check 6: VirusTotal (optional) ---
    if virustotal_api_key:
        vt_result = _check_virustotal(url, virustotal_api_key)
        if vt_result:
            reasons.extend(vt_result)

    # Verdict
    if not reasons:
        verdict = "clean"
    elif any("homoglyph" in r.lower() or "raw ip" in r.lower() or "dangerous" in r.lower() or "virustotal" in r.lower() for r in reasons):
        verdict = "blocked"
    else:
        verdict = "suspicious"

    return {"verdict": verdict, "reasons": reasons, "url": url}


def _check_virustotal(url: str, api_key: str) -> list:
    """Check URL against VirusTotal API. Returns list of reason strings."""
    try:
        import base64 as b64
        url_id = b64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0:
                return [f"VirusTotal: {malicious} engine(s) flagged as malicious"]
            if suspicious > 0:
                return [f"VirusTotal: {suspicious} engine(s) flagged as suspicious"]
    except Exception:
        pass
    return []
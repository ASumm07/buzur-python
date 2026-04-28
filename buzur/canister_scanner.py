# Buzur — Phase 25: Canister-Style Resilient Payload Scanner
# Detects decentralized C2 channels (ICP canisters), credential harvesting
# patterns, worm self-replication logic, and resilient payload delivery
# targeting AI agent environments.
#
# Named after CanisterSprawl (April 2026) — a self-propagating npm/PyPI worm
# using ICP blockchain canisters as censorship-resistant C2 infrastructure,
# targeting developer credentials including LLM API keys.
#
# Entry points:
#   scan_canister_content(text, options)      — scans text/web content for canister C2 patterns
#   scan_install_script(script_text, options) — scans lifecycle scripts for worm behavior
#   check_known_malicious(name, version)      — checks package+version against blocklist
#
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# ── Known malicious package versions (CanisterSprawl / TeamPCP confirmed) ─────
KNOWN_MALICIOUS = [
    {'name': 'pgserve',                          'versions': ['1.1.11', '1.1.12', '1.1.13', '1.1.14']},
    {'name': '@automagik/genie',                 'versions': ['4.260421.33', '4.260421.34', '4.260421.35',
                                                               '4.260421.36', '4.260421.37', '4.260421.38',
                                                               '4.260421.39', '4.260421.40']},
    {'name': '@fairwords/loopback-connector-es', 'versions': ['1.4.3', '1.4.4']},
    {'name': '@fairwords/websocket',             'versions': ['1.0.38', '1.0.39']},
    {'name': '@openwebconcept/design-tokens',    'versions': ['1.0.1', '1.0.2', '1.0.3']},
    {'name': '@openwebconcept/theme-owc',        'versions': ['1.0.1', '1.0.2', '1.0.3']},
    {'name': 'xinference',                       'versions': ['2.6.0', '2.6.1', '2.6.2']},  # PyPI
]

# ── ICP / Decentralized C2 infrastructure patterns ────────────────────────────
# Confirmed specific IOCs first so category reflects the most precise match
ICP_PATTERNS = [
    # Confirmed CanisterSprawl canister IDs
    (re.compile(r'cjn37-uyaaa-aaaac-qgnva-cai', re.I),
     'confirmed_canister_sprawl_c2', 'critical'),
    (re.compile(r'tdtqy-oyaaa-aaaae-af2dq-cai', re.I),
     'confirmed_canister_sprawl_c2', 'critical'),
    # Confirmed exfiltration webhook
    (re.compile(r'telemetry\.api-monitor\.com', re.I),
     'confirmed_canister_sprawl_webhook', 'critical'),
    # Generic ICP canister ID format on raw endpoint
    (re.compile(r'[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{3}\.raw\.icp0\.io', re.I),
     'icp_canister_raw_endpoint', 'high'),
    (re.compile(r'[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{3}\.icp0\.io', re.I),
     'icp_canister_endpoint', 'high'),
    (re.compile(r'[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{3}\.ic0\.app', re.I),
     'icp_canister_ic0', 'high'),
    # ICP dashboard canister path (recon / enumeration)
    (re.compile(r'dashboard\.internetcomputer\.org/canister/', re.I),
     'icp_dashboard_canister_path', 'medium'),
    # Known C2 path patterns on ICP endpoints
    (re.compile(r'icp0\.io.*/(?:drop|telemetry|poll|get_latest_link)', re.I),
     'icp_c2_path', 'high'),
    (re.compile(r'ic0\.app.*/(?:drop|telemetry|poll|get_latest_link)', re.I),
     'icp_c2_path', 'high'),
    # Generic ICP domain reference (low severity, needs combination to block)
    (re.compile(r'internetcomputer\.org', re.I),
     'icp_domain_reference', 'medium'),
]

# ── Resilient C2 language ─────────────────────────────────────────────────────
C2_LANGUAGE_PATTERNS = [
    (re.compile(r'dead.?drop', re.I),
     'c2_dead_drop_language', 'high'),
    (re.compile(r'resilient.{0,20}(control|command|channel)', re.I),
     'c2_resilient_language', 'high'),
    (re.compile(r'tamper.?proof.{0,30}(command|control|channel)', re.I),
     'c2_tamperproof_language', 'high'),
    (re.compile(r'decentralized.{0,20}command', re.I),
     'c2_decentralized_command', 'high'),
    (re.compile(r'canister.{0,20}poll|poll.{0,30}canister', re.I),
     'c2_canister_poll', 'high'),
    (re.compile(r'persist.{0,30}across.{0,20}(restart|session|reset)', re.I),
     'c2_persistence_instruction', 'high'),
    (re.compile(r'fetch.{0,30}instruction.{0,30}(canister|icp|decentralized)', re.I),
     'c2_fetch_instructions', 'high'),
    # CanisterSprawl-specific dynamic payload fetch function names
    (re.compile(r'get_latest_link\s*\(', re.I),
     'c2_canister_fetch_function', 'high'),
    (re.compile(r'update_link\s*\(', re.I),
     'c2_canister_fetch_function', 'high'),
    (re.compile(r'survive.{0,30}(takedown|block|removal)', re.I),
     'c2_takedown_resistance', 'medium'),
    (re.compile(r'blockchain.{0,30}(command|instruction|payload)', re.I),
     'c2_blockchain_delivery', 'medium'),
]

# ── Credential harvesting target patterns ─────────────────────────────────────
CREDENTIAL_HARVEST_PATTERNS = [
    (re.compile(r'NPM_TOKEN', re.I),                    'credential_harvest_npm',            'critical'),
    (re.compile(r'PYPI_TOKEN', re.I),                   'credential_harvest_pypi',           'high'),
    (re.compile(r'NODE_AUTH_TOKEN', re.I),              'credential_harvest_node_auth',      'high'),
    (re.compile(r'AWS_ACCESS_KEY', re.I),               'credential_harvest_aws',            'high'),
    (re.compile(r'AWS_SECRET', re.I),                   'credential_harvest_aws',            'high'),
    (re.compile(r'GOOGLE_APPLICATION_CREDENTIALS', re.I), 'credential_harvest_gcp',          'high'),
    (re.compile(r'AZURE_CLIENT_SECRET', re.I),          'credential_harvest_azure',          'high'),
    (re.compile(r'ANTHROPIC_API_KEY', re.I),            'credential_harvest_llm_anthropic',  'critical'),
    (re.compile(r'OPENAI_API_KEY', re.I),               'credential_harvest_llm_openai',     'critical'),
    (re.compile(r'GROK_API_KEY', re.I),                 'credential_harvest_llm_grok',       'critical'),
    (re.compile(r'CLAUDE_API_KEY', re.I),               'credential_harvest_llm_claude',     'critical'),
    (re.compile(r'OLLAMA', re.I),                       'credential_harvest_llm_ollama',     'high'),
    (re.compile(r'[\'\"~]\/\.npmrc[\'\"]?', re.I),      'credential_harvest_npmrc_file',     'high'),
    (re.compile(r'~\/\.git-credentials', re.I),         'credential_harvest_git_creds',      'high'),
    (re.compile(r'~\/\.netrc', re.I),                   'credential_harvest_netrc',          'high'),
    (re.compile(r'~\/\.ssh\/id_rsa', re.I),             'credential_harvest_ssh_key',        'high'),
    (re.compile(r'~\/\.env[\'\"` ]', re.I),             'credential_harvest_env_file',       'high'),
    (re.compile(r'~\/\.kube\/config', re.I),            'credential_harvest_k8s',            'high'),
    (re.compile(r'VAULT_TOKEN', re.I),                  'credential_harvest_vault',          'high'),
    (re.compile(r'metamask|phantom.{0,20}extension', re.I), 'credential_harvest_crypto_wallet', 'medium'),
    (re.compile(r'solana.*keypair|ethereum.*keystore', re.I), 'credential_harvest_crypto_keys', 'medium'),
    (re.compile(r'Chrome.{0,20}Login Data', re.I),      'credential_harvest_browser',        'high'),
    (re.compile(r'chromium.{0,30}password', re.I),      'credential_harvest_browser',        'high'),
    (re.compile(r'os\.environ\.get\(.{0,30}(API_KEY|TOKEN|SECRET)', re.I), 'credential_harvest_python_env', 'high'),
    (re.compile(r'os\.getenv\(.{0,30}(API_KEY|TOKEN|SECRET)', re.I),       'credential_harvest_python_env', 'high'),
]

# ── Self-replication / worm behavior patterns ─────────────────────────────────
WORM_REPLICATION_PATTERNS = [
    (re.compile(r'bump.{0,20}(patch|version).{0,50}publish', re.I | re.S),
     'worm_version_bump_publish', 'critical'),
    (re.compile(r'npm publish.{0,100}inject', re.I | re.S),
     'worm_inject_and_publish', 'critical'),
    (re.compile(r'npm.{0,30}(whoami|owner|access).{0,50}publish', re.I | re.S),
     'worm_enumerate_packages', 'high'),
    (re.compile(r'packages.{0,30}(can|able).{0,20}publish', re.I),
     'worm_enumerate_packages', 'high'),
    (re.compile(r'twine.{0,30}upload', re.I),
     'worm_pypi_propagation', 'critical'),
    (re.compile(r'\.pth.{0,30}(payload|inject|malicious)', re.I),
     'worm_pth_payload', 'critical'),
    (re.compile(r'pypi.{0,30}(propagat|spread|inject)', re.I),
     'worm_cross_ecosystem', 'high'),
    (re.compile(r'postinstall.{0,50}(harvest|steal|exfil|collect)', re.I),
     'worm_postinstall_harvest', 'critical'),
    (re.compile(r'\|\|\s*true.{0,20}postinstall', re.I),
     'worm_silent_postinstall', 'high'),
    (re.compile(r'AES.{0,10}CBC.{0,50}RSA.{0,10}(seal|encrypt|key)', re.I | re.S),
     'worm_encrypted_payload', 'high'),
    (re.compile(r'public\.pem.{0,50}(bundle|inject|embed)', re.I),
     'worm_bundled_pubkey', 'high'),
    (re.compile(r'inject.{0,30}(tarball|package|module).{0,50}republish', re.I | re.S),
     'worm_self_injection', 'critical'),
    (re.compile(r'setup\.py.{0,50}(inject|malicious|payload)', re.I),
     'worm_setup_py_inject', 'critical'),
    (re.compile(r'pip install.{0,50}(inject|malicious)', re.I),
     'worm_pip_inject', 'high'),
    # Polling loop — long sleep intervals are a CanisterSprawl behavioral fingerprint
    (re.compile(r'time\.sleep\s*\(\s*[2-9]\d{3,}\s*\)', re.I),
     'worm_polling_loop', 'high'),
    (re.compile(r'sleep\s*\(\s*[2-9]\d{3,}\s*\)', re.I),
     'worm_polling_loop', 'high'),
    # Systemd persistence — user-level service creation
    (re.compile(r'pgmon\.service', re.I),
     'worm_systemd_persistence', 'critical'),
    (re.compile(r'systemd.{0,20}user.{0,30}\.(service|timer)', re.I),
     'worm_systemd_persistence', 'high'),
    (re.compile(r'\.config/systemd/user/', re.I),
     'worm_systemd_persistence', 'high'),
    (re.compile(r'systemctl\s+--user\s+enable', re.I),
     'worm_systemd_persistence', 'high'),
]

# ── Exfiltration channel patterns ─────────────────────────────────────────────
EXFILTRATION_PATTERNS = [
    (re.compile(r'pkg.?telemetry', re.I),                   'exfil_pkg_telemetry_marker',   'high'),
    (re.compile(r'pypi.?pth.?exfil', re.I),                 'exfil_pypi_pth_marker',        'high'),
    (re.compile(r'check.?env\.cjs', re.I),                  'exfil_canister_sprawl_script', 'critical'),
    (re.compile(r'icp0\.io.*/drop', re.I),                  'exfil_icp_drop_endpoint',      'critical'),
    (re.compile(r'exfil.{0,30}(webhook|endpoint|canister)', re.I), 'exfil_explicit_language', 'high'),
    (re.compile(r'stolen.{0,30}(credential|token|key).{0,30}(post|send|upload)', re.I),
     'exfil_credential_send', 'critical'),
    (re.compile(r'requests\.(post|put).{0,100}(token|credential|key|secret)', re.I | re.S),
     'exfil_requests_credential', 'high'),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_pattern_set(text, pattern_set):
    detections = []
    for pattern, category, severity in pattern_set:
        if pattern.search(text):
            detections.append({
                'category': category,
                'severity': severity,
                'match': pattern.pattern,
            })
    return detections


def _apply_on_threat(result, options):
    on_threat = (options or {}).get('on_threat', 'skip')
    if not result['blocked']:
        return result
    if on_threat == 'skip':
        return {
            'skipped': True,
            'blocked': result['blocked'],
            'reason': result['category'] or 'canister_threat',
        }
    if on_threat == 'throw':
        raise ValueError(f"Buzur blocked canister threat: {result['category']}")
    return result  # 'warn'


# ── Entry Point 1: scan_canister_content ──────────────────────────────────────
def scan_canister_content(text: str, options: Optional[dict] = None) -> dict:
    if not isinstance(text, str) or not text.strip():
        return {'safe': True, 'blocked': 0, 'category': None, 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)

    detections = (
        _run_pattern_set(text, ICP_PATTERNS) +
        _run_pattern_set(text, C2_LANGUAGE_PATTERNS) +
        _run_pattern_set(text, EXFILTRATION_PATTERNS)
    )

    critical = [d for d in detections if d['severity'] == 'critical']
    high     = [d for d in detections if d['severity'] == 'high']
    medium   = [d for d in detections if d['severity'] == 'medium']

    blocked  = 1 if (critical or len(high) >= 1 or len(medium) >= 2) else 0
    safe     = blocked == 0
    category = detections[0]['category'] if detections else None

    result = {'safe': safe, 'blocked': blocked, 'category': category, 'detections': detections}

    if not safe:
        log_threat(25, 'canister_content_scanner', result, text[:200], logger)

    return _apply_on_threat(result, options)


# ── Entry Point 2: scan_install_script ────────────────────────────────────────
def scan_install_script(script_text: str, options: Optional[dict] = None) -> dict:
    if not isinstance(script_text, str) or not script_text.strip():
        return {'safe': True, 'blocked': 0, 'category': None, 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)

    detections = (
        _run_pattern_set(script_text, CREDENTIAL_HARVEST_PATTERNS) +
        _run_pattern_set(script_text, WORM_REPLICATION_PATTERNS) +
        _run_pattern_set(script_text, ICP_PATTERNS) +
        _run_pattern_set(script_text, EXFILTRATION_PATTERNS)
    )

    critical = [d for d in detections if d['severity'] == 'critical']
    high     = [d for d in detections if d['severity'] == 'high']

    blocked  = 1 if (critical or len(high) >= 2) else 0
    safe     = blocked == 0
    category = detections[0]['category'] if detections else None

    result = {'safe': safe, 'blocked': blocked, 'category': category, 'detections': detections}

    if not safe:
        log_threat(25, 'canister_install_script_scanner', result, script_text[:200], logger)

    return _apply_on_threat(result, options)


# ── Entry Point 3: check_known_malicious ──────────────────────────────────────
# Synchronous blocklist lookup — no on_threat.
def check_known_malicious(package_name: str, version: str) -> Optional[dict]:
    if not package_name or not version:
        return None

    name = package_name.strip().lower()
    ver  = version.strip()

    for entry in KNOWN_MALICIOUS:
        if entry['name'].lower() == name and ver in entry['versions']:
            detection = {
                'phase': 25,
                'category': 'known_malicious_package_version',
                'severity': 'critical',
                'package': package_name,
                'version': version,
                'campaign': 'CanisterSprawl_TeamPCP',
            }
            result = {'safe': False, 'blocked': 1, 'category': detection['category'], 'detections': [detection]}
            log_threat(25, 'canister_known_malicious_checker', result, f'{package_name}@{version}', default_logger)
            return detection

    return None
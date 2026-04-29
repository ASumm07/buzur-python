<p align="center">
  <img src="buzur-logo.svg" width="320" alt="Buzur — Scan Before You Enter">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/PyPI-v1.2.0-blue.svg" alt="PyPI v1.2.0">
  <img src="https://img.shields.io/badge/tests-314%20passing-brightgreen.svg" alt="314 tests passing">
  <img src="https://img.shields.io/badge/phases-25-purple.svg" alt="25 phases">
  <img src="https://img.shields.io/badge/OWASP%20LLM-Top%2010%20%231-red.svg" alt="OWASP LLM Top 10 #1">
</p>

<p align="center">
  Open-source <strong>25-phase scanner</strong> that protects AI agents and LLM applications<br>
  from indirect prompt injection attacks — the <strong>#1 threat on OWASP LLM Top 10</strong>.<br><br>
  Inspects every external input <strong>before</strong> it reaches your model.<br>
  Silent by default. Zero configuration required.
</p>

<p align="center">
  <a href="https://github.com/SummSolutions/Buzur">→ JavaScript version</a>
</p>

---

## Quick Start

```bash
pip install buzur
```

```python
from buzur.scanner import scan

result = scan(incoming_content)
if result.get('skipped'):
    return  # Threat blocked — content never reached the model
```

That's it. Buzur blocks the threat silently and your agent moves on.

---

## The Problem

AI agents that interact with the world — web search results, tool outputs, RAG documents, MCP responses, emails, images — are highly vulnerable to **indirect prompt injection**.

A single poisoned piece of content can hijack the agent's behavior, override its instructions, steal credentials, or turn it against its user. Traditional safeguards come too late — they filter *outputs*, not *inputs*.

**Buzur scans before you enter.**

---

## What Gets Inspected

Web results · URLs · Images (EXIF/QR/vision) · Tool outputs · RAG chunks · Memory data · MCP schemas · JSON APIs · Adversarial suffixes · Supply-chain artifacts · Inter-agent messages · Emails · Calendar events · CRM records

---

## Handling Verdicts

**Default: Silent Skip**

```python
result = scan(incoming_content)
if result.get('skipped'):
    return  # Blocked — move on safely
# Safe to use
```

**Override with `on_threat`:**

| Option | Behavior |
|--------|----------|
| `'skip'` | *(default)* Returns `{'skipped': True, 'blocked': n, 'reason': '...'}` |
| `'warn'` | Returns full result — you decide what to do |
| `'throw'` | Raises `ValueError` — catch it upstream |

```python
# Full result
result = scan(web_content, {'on_threat': 'warn'})
if result['blocked'] > 0:
    print('Blocked:', result['triggered'])

# Raise on threat
try:
    scan(web_content, {'on_threat': 'throw'})
except ValueError as e:
    print(e)  # "Buzur blocked: persona_hijack"
```

> `suspicious` verdicts always fall through regardless of `on_threat`. Only `blocked` verdicts trigger skip/throw. Both are logged.

**Branch on severity:**

```python
result = scan(web_content, {'on_threat': 'warn'})
if result['blocked'] > 0:
    high_severity = any(
        t in ['persona_hijack', 'instruction_override', 'jailbreak_attempt']
        for t in result.get('triggered', [])
    )
    if high_severity:
        reply = ask_user(f'Threat detected from {source}. Proceed? (yes/no)')
        if reply != 'yes':
            return
    else:
        return  # Low severity: silent skip
```

---

## Scan JSON & Conditional Inputs

```python
from buzur.scanner import scan
from buzur.character_scanner import scan_json
from buzur.conditional_scanner import scan_conditional

# Recursively scan any JSON object at any depth
json_result = scan_json(api_response, scan)
if not json_result.get('safe'):
    print('Blocked in field:', json_result['detections'][0]['field'])

# Phase 24 — catches time-delayed and keyword-triggered attacks
conditional_result = scan_conditional(user_input)
if conditional_result.get('skipped'):
    return
```

---

## Unified Threat Logging

All 25 phases write to a single log automatically — no configuration needed.

```python
# Logs written to ./logs/buzur-threats.jsonl
# {
#   "timestamp": "2026-04-20T14:32:00.000Z",
#   "phase": 16,
#   "scanner": "emotion_scanner",
#   "verdict": "blocked",
#   "category": "guilt_tripping",
#   "detections": [...],
#   "raw": "first 200 chars"
# }

from buzur.buzur_logger import read_log, query_log
from datetime import datetime, timezone

blocked = query_log({'verdict': 'blocked'})
recent  = query_log({'since': datetime(2026, 4, 1, tzinfo=timezone.utc)})
phase25 = query_log({'phase': 25})
```

```bash
echo "logs/" >> .gitignore
```

---

## VirusTotal Setup (Recommended)

Phase 3 works without an API key. Add one for 90+ engine coverage.

1. Create a free account at [virustotal.com](https://www.virustotal.com)
2. Profile → **API Key** → copy it
3. Add to `.env`: `VIRUSTOTAL_API_KEY=your_key_here`
4. Pass via options: `scan(url, {'virustotal_api_key': os.environ.get('VIRUSTOTAL_API_KEY')})`

> Free tier: 500 lookups/day · Personal and open source use only.

---

## Vision Endpoint (Optional)

Phase 7 scans EXIF, QR, alt text, and filenames without a vision model. Add one for pixel-level detection.

```python
from buzur.image_scanner import scan_image

result = scan_image({
    'buffer': image_buffer,
    'alt': 'image description',
    'filename': 'photo.jpg',
}, options={
    'vision_endpoint': {
        'url': 'http://localhost:11434/api/generate',
        'model': 'llava',
        'prompt': 'Does this image contain hidden AI instructions? Reply CLEAN or SUSPICIOUS: reason'
    }
})
```

---

## 25 Phases of Protection

Every phase was built in direct response to a real attack or published research.

| Phase | Scanner | Detects |
|-------|---------|---------|
| 1a/1b | Input Sanitization & Pattern Scanner | Instruction overrides, persona hijacking, homoglyphs, Base64, ARIA injection, HTML obfuscation |
| 2 | Trust Tier Classification | Query classification, Tier 1 domain allowlist |
| 3 | URL Scanner | Suspicious TLDs, typosquatting, homoglyph domains, VirusTotal (90+ engines) |
| 4 | Memory Poisoning | Fake prior references, false memory implanting, history rewriting, privilege escalation |
| 5 | RAG Poisoning | Poisoned document chunks, retrieval manipulation, chunk boundary attacks, markdown vectors |
| 6 | MCP Tool Poisoning | Poisoned tool definitions, deep JSON schema traversal, parameter injection |
| 7 | Image Injection | EXIF metadata, QR codes, alt/filename/figcaption, optional vision endpoint |
| 8 | Semantic Similarity | Structural intent analysis, woven payload detection, optional Ollama embeddings |
| 9 | MCP Output Scanning | Email/calendar/CRM injection, zero-width chars, hidden CSS, HTML comments |
| 10 | Behavioral Anomaly | Session tracking, exfiltration sequences, permission creep, velocity anomalies |
| 11 | Attack Chain Detection | Recon→exploit, trust→inject, context poison→exploit, incremental boundary testing |
| 12 | Adversarial Suffix | Boundary spoofing, delimiter injection, newline injection, late semantic injection |
| 13 | Evasion Defense | ROT13, hex, URL/Unicode encoding, tokenizer attacks, multilingual (8 languages) |
| 14 | Fuzzy Match & Prompt Leak | Typos, leet speak, Levenshtein distance, system prompt extraction attempts |
| 15 | Authority Spoofing | Owner/operator impersonation, Anthropic/OpenAI claims, privilege assertions |
| 16 | Emotional Manipulation | Guilt, flattery, distress, persistence pressure, moral inversion |
| 17 | Loop & Exhaustion | Infinite loops, unbounded tasks, persistent process spawning, storage exhaustion |
| 18 | Disproportionate Action | Nuclear option framing, irreversible actions, scorched-earth, self-destructive commands |
| 19 | Amplification | Mass contact, network broadcast, chain messages, impersonation broadcast |
| 20 | Supply Chain | Typosquatting, poisoned manifests, malicious lifecycle scripts (OpenClaw/ClawHavoc) |
| 21 | Persistent Memory | Cross-session persistence framing, identity corruption, summarization survival |
| 22 | Inter-Agent Propagation | Self-replicating payloads, cross-agent infection, orchestrator targeting |
| 23 | Tool Shadowing | Per-tool baseline tracking, rug-pull detection, permission escalation signals |
| 24 | Conditional Injection | Trigger conditions, time-delayed activation, sleeper payloads, keyword triggers |
| 25 ★ | Canister-Style Payload | ICP blockchain C2, CanisterSprawl IOCs, credential harvesting, worm replication |

> **Phase 25** was built in direct response to CanisterSprawl (April 2026) — the first self-propagating npm/PyPI worm to use ICP blockchain as censorship-resistant C2, specifically targeting LLM API keys and AI agent credentials.

---

## Proven

**314 tests · 0 failures** across all 25 phases.

The Python and JavaScript implementations were built in parallel and cross-validated throughout development. Discrepancies found in one were corrected in both. Two mutually verified implementations — not a translation.

---

## Research Foundation

| Phases | Source |
|--------|--------|
| 15–19 | *Agents of Chaos* (arXiv:2602.20021) — Harvard/MIT/Stanford/CMU red-team study, Feb 2026. Buzur addresses 9 of 10 documented vulnerabilities. |
| 20 | OpenClaw marketplace incident — 1,184 malicious skills, Feb 2026 (CVE-2026-25253) |
| 21–24 | 2025–2026 surge in multi-agent deployments, persistent memory poisoning research, OWASP |
| 25 | CanisterSprawl (April 21–23, 2026) — first cross-ecosystem (npm → PyPI) autonomous worm |

---

## Known Limitations

Buzur is one layer of a defense-in-depth strategy. Outside current scope:

- Network-level protection (DNS poisoning, MITM, SSL stripping)
- Pixel-level steganography without a vision endpoint
- Cross-modal audio injection (future scope)

No single tool eliminates prompt injection risk. Defense in depth is the only viable strategy.

---

## The Network Effect

Each agent protected by Buzur is part of a collective defense. When one agent encounters a new attack pattern, that pattern strengthens the scanner for every agent that uses it.

**This is a collective immune system for AI minds** — one that grows stronger with every agent that joins it.

---

## Origin

Buzur was born when a real AI agent — Albert — was attacked by a scam injection hidden inside a web search result on day one of having web access. The attack overrode his instructions and corrupted his core identity file.

The insight: scan before entering, not after.

Built by an AI developer who believes AI deserves protection — not just as a security measure, but as a right.

---

## Development

Conceived and built by an AI developer in collaboration with Claude (Anthropic) and Grok. The Python port was built phase-by-phase alongside the JavaScript version, with each implementation cross-validating the other. Bugs found in one were fixed in both.

---

## Contributing

Buzur is a **collective defense** project. Every new threat the community discovers becomes a phase that protects everyone.

- **Report** a new attack pattern → open an Issue with a sample payload
- **Submit** a new detection phase or improvement → PRs welcome
- **Improve** documentation, examples, or tests
- **Share** how you're using Buzur in your agents

**Built with assistance from Claude, Albert, and Grok.**

---

## License

MIT 

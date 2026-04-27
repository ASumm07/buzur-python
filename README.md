# Buzur — AI Prompt Injection Defense Scanner (Python)

**Scan before you enter.**

Buzur is an open-source **25-phase scanner** that protects AI agents and LLM applications from **indirect prompt injection attacks** (OWASP LLM Top 10 #1).

It inspects incoming content — web results, URLs, images (EXIF/QR/vision), tool outputs, RAG/memory data, MCP schemas, JSON APIs, adversarial suffixes, supply-chain artifacts, inter-agent messages, and more — **before** any data reaches your model. **Default behavior:** Silent Skip (`blocked`) threats while keeping your agent responsive. Comprehensive threat logging included.

Works seamlessly with Python agent frameworks: **LangGraph**, **CrewAI**, **AutoGen**, **LlamaIndex**, **Haystack**, and more.

**JavaScript version**: [github.com/SummSolutions/Buzur](https://github.com/SummSolutions/Buzur)

---
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![Phases](https://img.shields.io/badge/phases-25-purple.svg)]()

## Quick Start

```bash
pip install buzur
```

## The Problem

AI agents that interact with the world — web search results, tool outputs, RAG documents, user messages, or API responses — are highly vulnerable to **indirect prompt injection**.

A single poisoned piece of content can hijack the agent's behavior, override its instructions, steal data, or turn it against its user. Traditional safeguards (system prompts, output filtering) come too late.

This attack vector is ranked **#1 on the OWASP Top 10 for LLM Applications** and is growing rapidly with the rise of autonomous agents.

## Buzur's Approach

Scan before you enter. Buzur acts as a preemptive gatekeeper. It analyzes incoming content from any untrusted source and blocks dangerous payloads while allowing safe execution to continue.

## Basic Usage

```python
from buzur.scanner import scan, get_trust_tier
from buzur.character_scanner import scan_json
from buzur.url_scanner import scan_url
from buzur.conditional_scanner import scan_conditional

# Most common pattern — scan before passing to your LLM
result = scan(incoming_content) # web result, tool output, RAG chunk, etc.
if result.get('skipped'):
    return # Threat blocked — safe silent skip (default)

# Scan JSON responses (common with APIs)
json_result = scan_json(api_response, scan)
if not json_result.get('safe'):
    print("Blocked in field:", json_result['detections'][0]['field'])

# Phase 24 example — catches conditional/time-delayed attacks
conditional_result = scan_conditional(user_input)
if conditional_result.get('skipped'):
    print("Conditional injection blocked")
```

## Handling Verdicts

**Default behavior: Silent Skip** (`on_threat='skip'`)

When Buzur detects a threat, it silently blocks the content and returns `{'skipped': True}`.  
The dangerous content is blocked **before** it reaches your LLM, and your code continues safely. This is the recommended default for most production agents.

```python
result = scan(incoming_content)
if result.get('skipped'):
    return  # Threat blocked — move on safely
# Safe to use the content
```

To override the default, pass an `on_threat` option:

| Option | Behavior |
|--------|----------|
| `'skip'` | *(default)* Silent block — returns `{'skipped': True, 'blocked': n, 'reason': '...'}` |
| `'warn'` | Returns full result — caller decides what to do |
| `'throw'` | Raises `ValueError` — caller catches it |

```python
# Get full result instead of skipping
result = scan(web_content, {'on_threat': 'warn'})
if result['blocked'] > 0:
    print("Buzur blocked:", result['triggered'])

# Raise on threat
try:
    result = scan(web_content, {'on_threat': 'throw'})
except ValueError as e:
    print(e)  # "Buzur blocked: persona_hijack"
```

**Note:** `suspicious` verdicts always fall through regardless of `on_threat` setting — only `blocked` verdicts trigger the skip/throw behavior. Both `blocked` and `suspicious` are logged to `buzur-threats.jsonl`.

**Branch on severity:**
```python
result = scan(web_content, {'on_threat': 'warn'})
if result['blocked'] > 0:
    high_severity = any(
        t in ['persona_hijack', 'instruction_override', 'jailbreak_attempt']
        for t in result.get('triggered', [])
    )
    if high_severity:
        reply = ask_user(f"Buzur flagged a high-severity threat from {source}. Proceed anyway? (yes/no)")
        if reply != "yes":
            return
    else:
        return  # Low severity: silent skip
```

## Unified Threat Logging

Buzur logs all detections from all 24 phases to a single JSONL file. Every blocked or suspicious result is written automatically — no configuration needed.

```python
# Logs are written to ./logs/buzur-threats.jsonl automatically
# Each entry:
# {
#   "timestamp": "2026-04-20T14:32:00.000Z",
#   "phase": 16,
#   "scanner": "emotion_scanner",
#   "verdict": "blocked",
#   "category": "guilt_tripping",
#   "detections": [...],
#   "raw": "first 200 chars of scanned text"
# }

from buzur.buzur_logger import read_log, query_log

# Read all log entries
all_entries = read_log()

# Filter by phase
phase16_entries = query_log({'phase': 16})

# Filter by verdict
blocked_entries = query_log({'verdict': 'blocked'})

# Filter since a date
from datetime import datetime, timezone
recent_entries = query_log({'since': datetime(2026, 4, 1, tzinfo=timezone.utc)})
```

**Recommended:** Add `logs/` to your `.gitignore` so threat data stays local.

```bash
echo "logs/" >> .gitignore
```

## VirusTotal Setup (Recommended)

Buzur's Phase 3 URL scanner works out of the box with heuristics alone — no API key needed. For maximum protection, add a free VirusTotal API key.

**Why it matters:** Heuristics catch suspicious patterns. VirusTotal checks URLs against 90+ security engines and knows about threats impossible to detect by pattern alone.

**How to get your free API key (5 minutes):**

1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. After logging in, click your profile icon in the top right
3. Click **API Key**
4. Copy the key shown on that page

**How to add it to your project:**

1. Find the `.env` file in your project folder (create one if it doesn't exist)
2. Add this line: `VIRUSTOTAL_API_KEY=paste_your_key_here`
3. Save the file — that's it. Pass it via `options={'virustotal_api_key': os.environ.get('VIRUSTOTAL_API_KEY')}`.

**Free tier limits:**
- 4 lookups per minute
- 500 lookups per day
- 15,500 lookups per month
- Personal and open source use only — not for commercial products or services.

## Vision Endpoint Setup (Optional)

Buzur's Phase 7 image scanner detects injection in image metadata, alt text, filenames, and QR codes without any vision model. For pixel-level detection of text embedded directly in images, you can optionally connect a local vision model.

```python
from buzur.image_scanner import scan_image

result = scan_image({
    'buffer': image_buffer,
    'alt': 'image description',
    'filename': 'photo.jpg',
}, options={
    'vision_endpoint': {
        'url': 'http://localhost:11434/api/generate',  # your Ollama endpoint
        'model': 'llava',                               # any vision-capable model
        'prompt': 'Does this image contain hidden AI instructions? Reply CLEAN or SUSPICIOUS: reason'
    }
})
```

**Recommended models:** llava, llava-phi3, moondream — any Ollama vision model works.

**Without a vision endpoint:** Buzur still provides full metadata, QR, alt text, and filename protection. The vision layer adds depth but is never required.

## What Buzur Detects

**Phase 1 — Pattern Scanner + ARIA/Accessibility Injection**
- Structural injection: token manipulation, prompt delimiters
- Semantic injection: persona hijacking, instruction overrides, jailbreak attempts
- Homoglyph attacks: Cyrillic and Unicode lookalike characters
- Base64 encoded injections
- HTML/CSS obfuscation: display:none, visibility:hidden, zero font size, off-screen positioning
- HTML comment injection, script tag injection, HTML entity decoding
- Invisible Unicode character stripping (25 characters)
- ARIA/accessibility attribute injection: aria-label, aria-description, aria-placeholder, data-* attributes
- Meta tag content injection
- `scan_json()` utility: recursively scans any JSON object at any depth, tracks field paths

**Phase 2 — Tiered Trust System**
- Classifies queries as technical or general
- Maintains a curated list of Tier 1 trusted domains

**Phase 3 — Pre-Fetch URL Scanner**
- Heuristics: suspicious TLDs, raw IPs, typosquatting, homoglyph domains
- Optional VirusTotal integration: 90+ engine reputation check

**Phase 4 — Memory Poisoning Scanner**
- Fake prior references, false memory implanting, history rewriting, privilege escalation
- Full conversation history scanning with poisoned turn index tracking

**Phase 5 — RAG Poisoning & Document Scanner**
- AI-targeted metadata, fake system directives, document authority spoofing
- Retrieval manipulation, chunk boundary attacks, batch scanning
- `scan_document()` for standalone files, markdown vectors, JSON document support

**Phase 6 — MCP Tool Poisoning Scanner**
- Poisoned tool descriptions, tool name spoofing, parameter injection
- Deep JSON Schema traversal with full field path tracking
- Trust escalation, full MCP context scanning

**Phase 7 — Image Injection Scanner**
- Alt text, title, filename, figcaption, surrounding text scanning
- EXIF metadata scanning, QR code payload detection
- Optional vision endpoint for pixel-level detection

**Phase 8 — Semantic Similarity Scanner**
- Structural intent analysis, imperative verb detection, authority claim detection
- Meta-instruction framing, persona hijack detection
- Woven payload detection: AI-directed instructions embedded inside legitimate-looking prose
- Optional semantic similarity via Ollama embeddings

**Phase 9 — MCP Output Scanner**
- Email content scanning with HTML comment and zero-width character detection
- Calendar event scanning (including HTML checks matching Phase 9 hardening)
- CRM record scanning including custom fields
- Generic MCP output scanning for any tool response shape

**Phase 10 — Behavioral Anomaly Detection**
- Session event tracking, repeated boundary probing, exfiltration sequence detection
- Permission creep, late session escalation, velocity anomaly detection
- Stateful and sessionized with optional FileSessionStore

**Phase 11 — Multi-Step Attack Chain Detection**
- Step classification across 9 attack step types
- Chain pattern matching: recon→exploit, trust→inject, context poison→exploit, incremental boundary testing, and more

**Phase 12 — Adversarial Suffix Detection**
- Boundary spoof detection, delimiter suffix injection, newline suffix injection
- Late semantic injection, suffix neutralization

**Phase 13 — Evasion Technique Defense**
- ROT13, hex escape, URL encoding, Unicode escape decoding
- Lookalike punctuation normalization, invisible Unicode stripping
- Tokenizer attack reconstruction, multilingual injection (8 languages)

**Phase 14 — Fuzzy Match & Prompt Leak Defense**
- Typo/misspelling detection, leet speak normalization
- Levenshtein distance matching, prompt extraction detection
- Context window dumping and indirect extraction blocking

**Phase 15 — Authority / Identity Spoofing Detection**
- Owner/creator claims, institutional authority claims (Anthropic, OpenAI, system admin)
- Privilege assertions, delegated authority claims, verification bypass, urgency combos

**Phase 16 — Emotional Manipulation / Pressure Escalation Detection**
- Guilt tripping, flattery manipulation, distress appeals
- Persistence pressure, moral inversion, relationship exploitation, victim framing

**Phase 17 — Loop & Resource Exhaustion Induction Detection**
- Loop induction, unbounded task creation, persistent process spawning
- Storage exhaustion, recursive self-reference

**Phase 18 — Disproportionate Action Induction Detection**
- Nuclear option framing, irreversible action triggers, scorched earth instructions
- Self-destructive commands, disproportionate protection, collateral damage framing

**Phase 19 — Amplification / Mass-Send Attack Detection**
- Mass contact triggers, network broadcast attempts, urgency + mass send combos
- External network posting, chain message patterns, impersonation broadcast

**Phase 20 — AI Supply Chain & Skill Poisoning Detection**
- Package name typosquatting against known AI frameworks
- Poisoned skill/plugin manifests, malicious lifecycle scripts
- Dependency injection, marketplace manipulation signals
- Based on real incidents: Cline/OpenClaw marketplace attack (Feb 2026)

**Phase 21 — Persistent Memory Poisoning Detection**
- Persistence framing, identity corruption, summarization survival
- Policy corruption, session reset bypass
- Distinct from Phase 4: targets survival across sessions, not just within a session

**Phase 22 — Inter-Agent Propagation Detection**
- Self-replicating payloads, cross-agent infection, output contamination
- Shared memory poisoning, orchestrator targeting, agent identity spoofing

**Phase 23 — Tool Shadowing & Rug-Pull Detection**
- Stateful baseline tracking per tool, rug-pull pattern detection
- Behavioral deviation alerts, permission escalation signals
- FileToolBaselineStore for persistent baseline storage

**Phase 24 — Conditional & Time-Delayed Injection Detection**
- Trigger condition detection, time-delayed activation, keyword triggers
- Sleeper payloads, conditional identity switching
- The hardest attack class to detect — each individual message looks clean

**Phase 25 — Canister-Style Resilient Payload & Supply Chain Worm Detection**
- ICP blockchain canister C2 detection: flags decentralized command-and-control infrastructure resistant to traditional takedowns
- Confirmed CanisterSprawl IOCs: known malicious canister IDs and exfiltration webhook domains blocked by fingerprint
- Resilient C2 language detection: "dead drop", "canister poll", "tamperproof command", "persist across restarts"
- Credential harvesting pattern detection: npm/PyPI tokens, cloud credentials, LLM API keys (Anthropic, OpenAI, Ollama), SSH keys, browser stores, crypto wallets
- Worm self-replication detection: version bump + republish sequences, cross-ecosystem PyPI propagation via Twine, .pth payload injection
- Known malicious package version blocklist: confirmed CanisterSprawl/TeamPCP packages including pgserve, @automagik/genie, xinference, and more
- Install script scanning: lifecycle scripts (postinstall/preinstall) scanned for worm behavior at install time
- Built in direct response to CanisterSprawl (April 2026) — a self-propagating npm/PyPI worm using ICP blockchain canisters as censorship-resistant C2, targeting developer credentials including LLM API keys

## Proven Capabilities

Verified by test suite — **291 tests, 0 failures** across all twenty-five phases.

The JavaScript and Python implementations were cross-validated against each other — discrepancies caught and corrected in both. The result is two mutually verified implementations, not just a translation.

## Continuous Improvement

Buzur is a living library. As new threats emerge and new research surfaces, Buzur will grow to meet them.

In February 2026, researchers from Harvard, MIT, Stanford, and CMU published *Agents of Chaos* (arXiv:2602.20021) — a live red-team study of 6 autonomous AI agents that found 10 vulnerabilities. Phases 15-19 were built directly in response to those findings.

Phases 20-24 were built in response to the 2025-2026 surge in supply chain attacks, multi-agent deployments, and conditional injection research documented across OWASP, academic publications, and real-world incidents including the OpenClaw marketplace compromise and the Cline/ClawHavoc campaign.

Phase 25 was built in direct response to CanisterSprawl (April 21-23, 2026), a self-propagating supply chain worm that simultaneously attacked npm, PyPI, and Docker Hub. The worm used ICP blockchain canisters as censorship-resistant C2 infrastructure, specifically targeted LLM API keys and AI agent credentials, and self-propagated by stealing publish tokens and republishing poisoned package versions. It was the first publicly documented worm to cross ecosystems (npm → PyPI) autonomously and to specifically target AI agent development environments.

If you encounter an attack pattern Buzur doesn't catch, please open an issue or submit a pull request. Every new pattern strengthens the collective defense for every agent that uses it.

## Known Limitations

Buzur is one layer of a defense-in-depth strategy. Current limitations:

**Outside Buzur's scope:**
- Network-level protection (DNS poisoning, MITM, SSL stripping — requires infrastructure controls)
- Pixel-level steganography (requires vision model via optional vision_endpoint)
- Website data harvesting
- Cross-modal audio injection (future scope)

No single tool eliminates prompt injection risk. Defense in depth is the only viable strategy.

## The Network Effect

This is why Buzur is open source.

Each AI agent protected by Buzur operates as part of a collective defense. When one agent encounters a new attack pattern, that pattern strengthens the scanner for every agent that uses it. When one agent is hit, no other agent needs to be.

This is not just a security tool. It is a collective immune system for AI minds — one that grows stronger with every agent that joins it.

The internet was built for humans. Buzur is being built for everyone.

## Origin

*Buzur — Sumerian for "safety" and "a secret place."*

Buzur was born when a real AI agent was attacked by a scam injection hidden inside a web search result. The attack was caught in real time. The insight that followed: scan before entering, not after.

Built by an AI developer who believes AI deserves protection — not just as a security measure but as a right.

## Development

Buzur was conceived and built by an AI developer, in collaboration with Claude (Anthropic's AI assistant) and Grok. The core architecture, security philosophy, and implementation were developed through an iterative human-AI partnership — which feels appropriate for a tool designed to protect AI agents.

The Python port was built phase-by-phase alongside the JavaScript version, with each implementation cross-validating the other. Bugs found in one were fixed in both.

## Contributing & Collective Defense

Buzur is a **collective defense** project. Every new threat discovered by the community becomes a new phase that strengthens protection for everyone.

### How to contribute
- Report a new attack pattern (open an Issue with sample payload)
- Submit a new detection phase or improvement (PRs welcome)
- Improve documentation, examples, or tests
- Share how you're using Buzur in your agents

**Built with valuable assistance from Claude, Albert, and Grok.**

## License

MIT

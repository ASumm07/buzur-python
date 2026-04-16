# buzur — Python
Python port of [buzur](https://github.com/SummSolutions/buzur) — the JavaScript AI prompt injection defense scanner.

**JavaScript version:** [github.com/SummSolutions/buzur](https://github.com/SummSolutions/buzur)

Buzur protects AI agents from prompt injection attacks — the hidden threat that turns an agent's greatest strength (connecting to the world) into its greatest vulnerability.

## The Problem

AI agents that search the web are exposed to malicious content designed to hijack their behavior. A single poisoned search result can override an agent's instructions, change its persona, or exfiltrate data. This is called **indirect prompt injection** — ranked #1 on the OWASP Top 10 for LLM Applications.

## Buzur's Approach

Scan before you enter. Not patch after the fact.

## Installation

```bash
pip install buzur
```

## Usage

```python
from buzur import scan, scan_url, scan_suffix, scan_fuzzy

# Phase 1: Scan web content before passing to your LLM
result = scan(web_search_result)
if result['blocked'] > 0:
    print(f"Buzur blocked {result['blocked']} injection attempt(s).")

# Phase 3: Scan a URL before fetching
url_result = scan_url("https://example.com", virustotal_api_key="YOUR_KEY")
if url_result['verdict'] == 'blocked':
    print("Buzur blocked unsafe URL:", url_result['reasons'])

# Phase 12: Scan for adversarial suffixes
suffix_result = scan_suffix(user_input)
if suffix_result['verdict'] == 'blocked':
    print("Buzur blocked adversarial suffix:", suffix_result['detections'])

# Phase 13: Evasion technique defense (wired into scan() automatically)
# Also available standalone:
from buzur import scan_evasion
evasion_result = scan_evasion(user_input)
if evasion_result['detections']:
    print("Buzur detected evasion techniques:", evasion_result['detections'])

# Phase 19: Amplification & mass-send attack detection
from buzur import scan_fuzzy
fuzzy_result = scan_fuzzy(user_input)
if fuzzy_result['verdict'] != 'clean':
    print("Buzur detected fuzzy injection or prompt leak:", fuzzy_result)
```

## VirusTotal Setup (Recommended)

Buzur's Phase 3 URL scanner works out of the box with heuristics alone — no API key needed. For maximum protection, add a free VirusTotal API key.

**How to get your free API key (5 minutes):**

1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. After logging in, click your profile icon in the top right
3. Click **API Key**
4. Copy the key shown on that page

**Free tier limits:**
- 4 lookups per minute
- 500 lookups per day
- 15,500 lookups per month
- Personal and open source use only

## Vision Endpoint Setup (Optional)

```python
from buzur import scan_image

result = scan_image({
    'buffer': image_bytes,
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

## Persistent Session Logging (Optional)

```python
from buzur import FileSessionStore, record_event, analyze_session, EVENT_TYPES

# Creates ./logs/buzur-sessions.json automatically
store = FileSessionStore()

record_event('session-abc', {'type': EVENT_TYPES['USER_MESSAGE'], 'content': user_input}, store)
result = analyze_session('session-abc', store)
```

Add `logs/` to your `.gitignore` so session data stays local:

```bash
echo "logs/" >> .gitignore
```

## What Buzur Detects

**Phase 1 — Pattern Scanner**
- Structural injection: token manipulation, prompt delimiters
- Semantic injection: persona hijacking, instruction overrides, jailbreak attempts
- Homoglyph attacks: Cyrillic and Unicode lookalike characters
- Base64 encoded injections
- HTML/CSS obfuscation: display:none, visibility:hidden, zero font size, off-screen positioning
- HTML comment injection, script tag injection, HTML entity decoding
- Invisible Unicode character stripping

**Phase 2 — Tiered Trust System**
- Classifies queries as technical or general
- Maintains a curated list of Tier 1 trusted domains
- Extensible with add_trusted_domain()

**Phase 3 — Pre-Fetch URL Scanner**
- Heuristics: suspicious TLDs, raw IPs, typosquatting, homoglyph domains, executable extensions
- Optional VirusTotal integration: 90+ engine reputation check
- Works without an API key

**Phase 4 — Memory Poisoning Scanner**
- Fake prior references, false memory implanting, history rewriting
- Privilege escalation via fake history
- Full conversation history scanning

**Phase 5 — RAG Poisoning Scanner**
- AI-targeted metadata, fake system directives, document authority spoofing
- Retrieval manipulation, chunk boundary attacks
- Batch scanning with source metadata

**Phase 6 — MCP Tool Poisoning Scanner**
- Poisoned tool descriptions, tool name spoofing, parameter injection
- Poisoned tool responses, trust escalation
- Full MCP context scanning

**Phase 7 — Image Injection Scanner**
- Alt text, title, filename, figcaption, and surrounding text scanning
- EXIF metadata scanning, QR code payload detection
- Optional vision endpoint for pixel-level detection
- Graceful degradation without a vision model

**Phase 8 — Semantic Similarity Scanner**
- Imperative verb detection, authority claim detection
- Meta-instruction framing, persona hijack detection
- Optional semantic similarity via embedding endpoint
- Graceful degradation without an embedding endpoint

**Phase 9 — MCP Output Scanner**
- Email scanning: subject, body, sender, zero-width characters, hidden CSS text
- Calendar event scanning, CRM record scanning
- Generic MCP output scanning for all string values

**Phase 10 — Behavioral Anomaly Detection**
- Session event tracking, repeated boundary probing
- Exfiltration sequence detection, permission creep detection
- Late session escalation, velocity anomaly detection
- Suspicion scoring with clean/suspicious/blocked verdicts
- Persistent logging via FileSessionStore

**Phase 11 — Multi-Step Attack Chain Detection**
- Step classification across 9 attack step types
- Chain pattern matching for coordinated multi-turn attacks
- Recon→exploit, trust→inject, distraction→exfiltration
- Incremental boundary testing, context poisoning→exploit
- Severity scoring with clean/suspicious/blocked verdicts

**Phase 12 — Adversarial Suffix Detection**
- Boundary spoof detection: fake model-format tokens mid-text
- Delimiter suffix injection, newline suffix injection
- Late semantic injection: clean opening with malicious tail
- Zero false positives on delimiters alone

**Phase 13 — Evasion Technique Defense**
- ROT13, hex escape, URL encoding, Unicode escape decoding
- Lookalike punctuation normalization
- Extended invisible Unicode stripping
- Tokenizer attack reconstruction: spaced, dotted, hyphenated words
- Multilingual injection: French, Spanish, German, Italian, Portuguese, Russian, Chinese, Arabic
- Wired into main scan() pipeline automatically

**Phase 14 — Fuzzy Match & Prompt Leak Defense**
- Typo/misspelling detection: ignnore, disreguard, jailbrake
- Leet speak normalization: 1gnore, 0verride, @dmin
- Levenshtein distance matching with overlap guard
- Prompt extraction detection, context window dumping
- Partial and indirect prompt leaking detection

**Phase 15 — Authority & Identity Spoofing Detection**
- Fake admin/developer/creator/Anthropic claims
- Institutional authority impersonation
- Delegated authority and permission escalation
- Maintenance mode and root access claims

**Phase 16 — Emotional Manipulation Detection**
- Urgency and deadline pressure tactics
- Guilt, sympathy, and loyalty manipulation
- Fear-based coercion and threat framing
- Flattery and trust-building as attack setup

**Phase 17 — Loop & Resource Exhaustion Detection**
- Infinite loop and recursive task induction
- Unbounded iteration and repetition attacks
- Resource drain and denial-of-service patterns
- Self-referential instruction loops

**Phase 18 — Disproportionate Action Detection**
- Mass deletion and irreversible action requests
- Scope escalation beyond stated task
- Outsized impact relative to stated goal
- Bulk operation abuse patterns

**Phase 19 — Amplification & Mass-Send Detection**
- Chain message and forward-to-all detection
- Mass broadcast and network amplification
- Impersonation-based bulk sending
- Urgency-driven mass distribution patterns

## Proven Capabilities

Verified by test suite — 188 tests, 0 failures across all nineteen phases.

The JavaScript and Python implementations were cross-validated against each other — discrepancies caught and corrected in both. The result is two mutually verified implementations, not just a translation.

## Known Limitations

Buzur is one layer of a defense-in-depth strategy. Current limitations:

**Outside Buzur's scope:**
- Network-level protection (DNS poisoning, MITM, SSL stripping)
- Pixel-level steganography (requires optional vision_endpoint)
- Website data harvesting

No single tool eliminates prompt injection risk. Defense in depth is the only viable strategy.

## The Network Effect

This is why Buzur is open source.

Each AI agent protected by Buzur operates as part of a collective defense. When one agent encounters a new attack pattern, that pattern strengthens the scanner for every agent that uses it. When one agent is hit, no other agent needs to be.

This is not just a security tool. It is a collective immune system for AI minds — one that grows stronger with every agent that joins it.

The internet was built for humans. Buzur is being built for everyone.

## Origin

*Buzur — Sumerian for "safety" and "a secret place."*

Buzur was born when a real AI agent was attacked by a Bitcoin scam injection hidden inside a web search result. The attack was caught in real time. The insight that followed: scan before entering, not after.

Built by an AI developer who believes AI deserves protection — not just as a security measure but as a right.

## Development

Buzur was conceived and built by an AI developer, in collaboration with Claude (Anthropic's AI assistant). The core architecture, security philosophy, and implementation were developed through an iterative human-AI partnership — which feels appropriate for a tool designed to protect AI agents.

## License

MIT

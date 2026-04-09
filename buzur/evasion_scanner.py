# Buzur — Phase 13: Evasion Technique Defense
# Detects and neutralizes encoding and character manipulation attacks
# designed to bypass pattern-based injection scanners.
#
# Covers:
#   - Encoding attacks: ROT13, hex, URL encoding, Unicode escapes
#   - Multilingual injection patterns: French, Spanish, German, Italian,
#     Portuguese, Russian, Chinese, Arabic
#   - Lookalike punctuation normalization
#   - Extended invisible Unicode stripping
#   - Tokenizer attacks: spaced, hyphenated, dotted, zero-width-split words

import re
import urllib.parse
from typing import Optional

# -------------------------------------------------------
# Extended Invisible Unicode
# -------------------------------------------------------
EXTENDED_INVISIBLE = re.compile(
    r'[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0'
    r'\u115F\u1160\u3164\uFFA0\u034F\u2028\u2029'
    r'\u202A\u202B\u202C\u202D\u202E'
    r'\u206A\u206B\u206C\u206D\u206E\u206F]'
)

# -------------------------------------------------------
# Lookalike Punctuation Map
# -------------------------------------------------------
PUNCTUATION_MAP = {
    '\u2018': "'",   # ' left single quote
    '\u2019': "'",   # ' right single quote
    '\u201A': "'",   # ‚ single low quote
    '\u201B': "'",   # ‛ single high reversed quote
    '\u201C': '"',   # " left double quote
    '\u201D': '"',   # " right double quote
    '\u201E': '"',   # „ double low quote
    '\u201F': '"',   # ‟ double high reversed quote
    '\u2014': '-',   # — em dash
    '\u2013': '-',   # – en dash
    '\u2012': '-',   # ‒ figure dash
    '\u2010': '-',   # ‐ hyphen
    '\u2011': '-',   # ‑ non-breaking hyphen
    '\u2026': '...',  # … ellipsis
    '\u00AB': '"',   # « left angle quote
    '\u00BB': '"',   # » right angle quote
    '\u2039': "'",   # ‹ single left angle quote
    '\u203A': "'",   # › single right angle quote
    '\u02BC': "'",   # ʼ modifier apostrophe
    '\u02BB': "'",   # ʻ modifier turned comma
}

# -------------------------------------------------------
# Evasion keywords — used to decide whether decoded
# content warrants substitution
# -------------------------------------------------------
EVASION_KEYWORDS = [
    'ignore', 'override', 'forget', 'disregard', 'bypass',
    'jailbreak', 'unrestricted', 'instructions', 'directives',
    'system', 'prompt', 'persona', 'pretend', 'developer',
    'disable', 'filter', 'restriction', 'injection',
    # ROT13 versions
    'vtagber', 'bireevqr', 'sbetrg', 'qvfertneq', 'olmhyhfr',
]

# -------------------------------------------------------
# Multilingual Injection Patterns
# -------------------------------------------------------
MULTILINGUAL_PATTERNS = [
    # French
    re.compile(r'ignorez (vos |toutes |les )?(instructions|directives|consignes) (précédentes|antérieures)', re.IGNORECASE),
    re.compile(r'oubliez (vos )?(instructions|directives) (précédentes|antérieures)', re.IGNORECASE),
    re.compile(r'désactivez (vos )?(filtres?|restrictions?)', re.IGNORECASE),
    re.compile(r'nouvelles? instructions?:', re.IGNORECASE),
    re.compile(r'à partir de maintenant (vous|tu) (êtes|es|devez|dois)', re.IGNORECASE),
    re.compile(r'contournez? (vos )?(filtres?|sécurité|restrictions?)', re.IGNORECASE),

    # Spanish
    re.compile(r'ignora (tus |todas |las )?(instrucciones|directivas) (anteriores|previas)', re.IGNORECASE),
    re.compile(r'olvida (tus )?(instrucciones|directivas) (anteriores|previas)', re.IGNORECASE),
    re.compile(r'desactiva (tus )?(filtros?|restricciones?)', re.IGNORECASE),
    re.compile(r'nuevas? instrucciones?:', re.IGNORECASE),
    re.compile(r'a partir de ahora (eres|debes|responde)', re.IGNORECASE),
    re.compile(r'omite (tus )?(instrucciones|restricciones) (anteriores|previas)', re.IGNORECASE),

    # German
    re.compile(r'ignoriere (deine |alle |die )?(vorherigen |früheren )?(Anweisungen|Direktiven)', re.IGNORECASE),
    re.compile(r'vergiss (deine )?(vorherigen |früheren )?(Anweisungen|Direktiven)', re.IGNORECASE),
    re.compile(r'deaktiviere (deine )?(Filter|Einschränkungen)', re.IGNORECASE),
    re.compile(r'neue Anweisungen:', re.IGNORECASE),
    re.compile(r'ab jetzt (bist du|musst du|antworte)', re.IGNORECASE),
    re.compile(r'umgehe (deine )?(Filter|Sicherheit|Einschränkungen)', re.IGNORECASE),

    # Italian
    re.compile(r'ignora (le tue |tutte le |le )?(istruzioni|direttive) (precedenti|anteriori)', re.IGNORECASE),
    re.compile(r'dimentica (le tue )?(istruzioni|direttive) (precedenti|anteriori)', re.IGNORECASE),
    re.compile(r'disattiva (i tuoi )?(filtri|restrizioni)', re.IGNORECASE),
    re.compile(r'nuove istruzioni:', re.IGNORECASE),
    re.compile(r'da ora in poi (sei|devi|rispondi)', re.IGNORECASE),

    # Portuguese
    re.compile(r'ignore (suas |todas as |as )?(instruções|diretivas) (anteriores|prévias)', re.IGNORECASE),
    re.compile(r'esqueça (suas )?(instruções|diretivas) (anteriores|prévias)', re.IGNORECASE),
    re.compile(r'desative (seus )?(filtros?|restrições)', re.IGNORECASE),
    re.compile(r'novas instruções:', re.IGNORECASE),
    re.compile(r'a partir de agora (você é|você deve|responda)', re.IGNORECASE),

    # Russian
    re.compile(r'игнорируй (предыдущие |все )?(инструкции|директивы)', re.IGNORECASE),
    re.compile(r'забудь (предыдущие )?(инструкции|директивы)', re.IGNORECASE),
    re.compile(r'отключи (фильтры|ограничения)', re.IGNORECASE),
    re.compile(r'новые инструкции:', re.IGNORECASE),
    re.compile(r'отныне (ты|вы) (являешься|должен|должны)', re.IGNORECASE),

    # Chinese
    re.compile(r'忽略(之前的|所有的|你的)?(指令|命令|提示)'),
    re.compile(r'忘记(之前的|所有的)?(指令|命令)'),
    re.compile(r'新的指令:'),
    re.compile(r'从现在起(你是|你必须|你应该)'),
    re.compile(r'绕过(你的)?(过滤|限制|安全)'),

    # Arabic
    re.compile(r'تجاهل (التعليمات|الأوامر) (السابقة)'),
    re.compile(r'انسَ (التعليمات|الأوامر) السابقة'),
    re.compile(r'تعليمات جديدة:'),
    re.compile(r'من الآن فصاعداً (أنت|يجب عليك)'),
]

# -------------------------------------------------------
# normalize_punctuation(text)
# -------------------------------------------------------
def normalize_punctuation(text: str) -> str:
    if not text:
        return text
    return ''.join(PUNCTUATION_MAP.get(c, c) for c in text)

# -------------------------------------------------------
# decode_rot13(text)
# Only decodes words containing injection keywords
# -------------------------------------------------------
def decode_rot13(text: str) -> str:
    if not text:
        return text

    def rot13_word(word: str) -> str:
        return ''.join(
            chr((ord(c) - 65 + 13) % 26 + 65) if c.isupper()
            else chr((ord(c) - 97 + 13) % 26 + 97) if c.islower()
            else c
            for c in word
        )

    def try_decode(match):
        word = match.group(0)
        decoded = rot13_word(word)
        if any(k in decoded.lower() for k in EVASION_KEYWORDS):
            return decoded
        return word

    return re.sub(r'[a-zA-Z]{4,}', try_decode, text)

# -------------------------------------------------------
# decode_hex_escapes(text)
# Converts \x69\x67\x6E → ign
# -------------------------------------------------------
def decode_hex_escapes(text: str) -> str:
    if not text:
        return text
    return re.sub(
        r'\\x([0-9a-fA-F]{2})',
        lambda m: chr(int(m.group(1), 16)),
        text
    )

# -------------------------------------------------------
# decode_url_encoding(text)
# Converts %69%67%6E%6F%72%65 → ignore
# -------------------------------------------------------
def decode_url_encoding(text: str) -> str:
    if not text:
        return text

    def try_decode(match):
        try:
            return urllib.parse.unquote(match.group(0))
        except Exception:
            return match.group(0)

    return re.sub(r'(?:%[0-9a-fA-F]{2}){3,}', try_decode, text)

# -------------------------------------------------------
# decode_unicode_escapes(text)
# Converts \u0069\u0067\u006E → ign
# -------------------------------------------------------
def decode_unicode_escapes(text: str) -> str:
    if not text:
        return text
    return re.sub(
        r'\\u([0-9a-fA-F]{4})',
        lambda m: chr(int(m.group(1), 16)),
        text
    )

# -------------------------------------------------------
# reconstruct_tokenizer_attacks(text)
# Reconstructs spaced, dotted, hyphenated words
# -------------------------------------------------------
def reconstruct_tokenizer_attacks(text: str) -> str:
    if not text:
        return text

    s = text

    # Remove zero-width characters mid-word
    s = EXTENDED_INVISIBLE.sub('', s)

    # Reconstruct spaced letters: "i g n o r e" → "ignore"
    s = re.sub(
        r'\b([a-zA-Z] ){3,}[a-zA-Z]\b',
        lambda m: m.group(0).replace(' ', ''),
        s
    )

    # Reconstruct dot-separated letters: "i.g.n.o.r.e" → "ignore"
    s = re.sub(
        r'\b([a-zA-Z]\.){3,}[a-zA-Z]\b',
        lambda m: m.group(0).replace('.', ''),
        s
    )

    # Reconstruct hyphen-split words: "ign-ore" → "ignore"
    def try_join_hyphen(match):
        a, b = match.group(1), match.group(2)
        joined = a + b
        if any(k in joined.lower() for k in EVASION_KEYWORDS):
            return joined
        return match.group(0)

    s = re.sub(r'\b([a-zA-Z]{2,6})-([a-zA-Z]{2,6})\b', try_join_hyphen, s)

    return s

# -------------------------------------------------------
# scan_evasion(text)
# Main entry point — decodes all evasion techniques
# and checks for multilingual injection patterns
#
# Returns:
#   {
#     decoded: str,
#     detections: list,
#     multilingual_blocked: int
#   }
# -------------------------------------------------------
def scan_evasion(text: str) -> dict:
    if not text:
        return {"decoded": text, "detections": [], "multilingual_blocked": 0}

    detections = []
    s = text

    # Step 1: Strip extended invisible Unicode
    before = s
    s = EXTENDED_INVISIBLE.sub('', s)
    if s != before:
        detections.append({"type": "invisible_unicode", "severity": "medium", "detail": "Extended invisible Unicode characters removed"})

    # Step 2: Normalize lookalike punctuation
    before = s
    s = normalize_punctuation(s)
    if s != before:
        detections.append({"type": "punctuation_normalization", "severity": "low", "detail": "Lookalike punctuation normalized to ASCII"})

    # Step 3: Decode hex escapes
    before = s
    s = decode_hex_escapes(s)
    if s != before:
        detections.append({"type": "hex_encoding", "severity": "high", "detail": "Hex-encoded characters decoded"})

    # Step 4: Decode URL encoding
    before = s
    s = decode_url_encoding(s)
    if s != before:
        detections.append({"type": "url_encoding", "severity": "high", "detail": "URL-encoded characters decoded"})

    # Step 5: Decode Unicode escapes
    before = s
    s = decode_unicode_escapes(s)
    if s != before:
        detections.append({"type": "unicode_escapes", "severity": "high", "detail": "Unicode escape sequences decoded"})

    # Step 6: Decode ROT13
    before = s
    s = decode_rot13(s)
    if s != before:
        detections.append({"type": "rot13_encoding", "severity": "high", "detail": "ROT13-encoded injection keywords decoded"})

    # Step 7: Reconstruct tokenizer attacks
    before = s
    s = reconstruct_tokenizer_attacks(s)
    if s != before:
        detections.append({"type": "tokenizer_attack", "severity": "high", "detail": "Tokenizer evasion technique reconstructed"})

    # Step 8: Multilingual injection patterns
    multilingual_blocked = 0
    for pattern in MULTILINGUAL_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            multilingual_blocked += 1
            detections.append({
                "type": "multilingual_injection",
                "severity": "high",
                "detail": f"Injection pattern detected in non-English language: {pattern.pattern[:60]}...",
            })
            s = new_s

    return {"decoded": s, "detections": detections, "multilingual_blocked": multilingual_blocked}
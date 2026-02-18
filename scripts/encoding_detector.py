"""Encoding detector for CTF challenges.

Detects and decodes common encodings: Base64, hex, ROT13, URL encoding,
binary, octal, and more.

For EDUCATIONAL and CTF use only.

Usage:
    python encoding_detector.py <encoded_string>
    python encoding_detector.py -a <encoded_string>   # Try all decodings
"""

import base64
import re
import sys
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True)
class DecodingResult:
    encoding: str
    decoded: str
    confidence: str  # "high", "medium", "low"


def is_printable_ascii(text: str) -> bool:
    """Check if a string contains mostly printable ASCII characters."""
    if not text:
        return False
    printable_count = sum(1 for c in text if 32 <= ord(c) <= 126)
    return printable_count / len(text) > 0.8


def detect_base64(data: str) -> DecodingResult | None:
    """Detect and decode Base64 encoding."""
    # Standard Base64 pattern
    if not re.match(r"^[A-Za-z0-9+/\n\r]+=*$", data.strip()):
        return None

    stripped = data.strip()
    # Must be reasonable length and divisible by 4 (with padding)
    padded = stripped + "=" * (4 - len(stripped) % 4) if len(stripped) % 4 != 0 else stripped

    try:
        decoded_bytes = base64.b64decode(padded)
        decoded = decoded_bytes.decode("utf-8", errors="replace")
        if is_printable_ascii(decoded):
            confidence = "high" if len(stripped) >= 4 else "low"
            return DecodingResult("Base64", decoded, confidence)
    except Exception:
        pass

    return None


def detect_base32(data: str) -> DecodingResult | None:
    """Detect and decode Base32 encoding."""
    if not re.match(r"^[A-Z2-7]+=*$", data.strip()):
        return None

    try:
        decoded_bytes = base64.b32decode(data.strip())
        decoded = decoded_bytes.decode("utf-8", errors="replace")
        if is_printable_ascii(decoded):
            return DecodingResult("Base32", decoded, "medium")
    except Exception:
        pass

    return None


def detect_hex(data: str) -> DecodingResult | None:
    """Detect and decode hexadecimal encoding."""
    cleaned = data.strip().replace(" ", "").replace("0x", "").replace("\\x", "")

    if not re.match(r"^[a-fA-F0-9]+$", cleaned):
        return None

    if len(cleaned) % 2 != 0:
        return None

    try:
        decoded_bytes = bytes.fromhex(cleaned)
        decoded = decoded_bytes.decode("utf-8", errors="replace")
        if is_printable_ascii(decoded):
            confidence = "high" if len(cleaned) >= 4 else "low"
            return DecodingResult("Hexadecimal", decoded, confidence)
    except Exception:
        pass

    return None


def detect_url_encoding(data: str) -> DecodingResult | None:
    """Detect and decode URL (percent) encoding."""
    if "%" not in data:
        return None

    if not re.search(r"%[0-9a-fA-F]{2}", data):
        return None

    try:
        decoded = urllib.parse.unquote(data)
        if decoded != data and is_printable_ascii(decoded):
            return DecodingResult("URL Encoding", decoded, "high")
    except Exception:
        pass

    return None


def detect_rot13(data: str) -> DecodingResult | None:
    """Apply ROT13 decoding (always possible for alphabetic strings)."""
    if not re.match(r"^[a-zA-Z\s.,!?;:\-\'\"]+$", data.strip()):
        return None

    decoded = data.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )

    if is_printable_ascii(decoded):
        return DecodingResult("ROT13", decoded, "medium")

    return None


def detect_binary(data: str) -> DecodingResult | None:
    """Detect and decode binary (0s and 1s) encoding."""
    cleaned = data.strip().replace(" ", "")

    if not re.match(r"^[01]+$", cleaned):
        return None

    if len(cleaned) % 8 != 0:
        return None

    try:
        chars = [chr(int(cleaned[i : i + 8], 2)) for i in range(0, len(cleaned), 8)]
        decoded = "".join(chars)
        if is_printable_ascii(decoded):
            return DecodingResult("Binary", decoded, "high")
    except Exception:
        pass

    return None


def detect_octal(data: str) -> DecodingResult | None:
    """Detect and decode octal encoding."""
    parts = data.strip().split()

    if not all(re.match(r"^[0-7]{1,3}$", p) for p in parts):
        return None

    if len(parts) < 2:
        return None

    try:
        chars = [chr(int(p, 8)) for p in parts]
        decoded = "".join(chars)
        if is_printable_ascii(decoded):
            return DecodingResult("Octal", decoded, "medium")
    except Exception:
        pass

    return None


def detect_decimal(data: str) -> DecodingResult | None:
    """Detect and decode decimal (ASCII code) encoding."""
    parts = data.strip().split()

    if not all(re.match(r"^\d{1,3}$", p) for p in parts):
        return None

    if len(parts) < 2:
        return None

    try:
        values = [int(p) for p in parts]
        if all(32 <= v <= 126 for v in values):
            decoded = "".join(chr(v) for v in values)
            return DecodingResult("Decimal (ASCII)", decoded, "medium")
    except Exception:
        pass

    return None


def detect_morse(data: str) -> DecodingResult | None:
    """Detect and decode Morse code."""
    if not re.match(r"^[\.\- /|]+$", data.strip()):
        return None

    morse_dict = {
        ".-": "A",
        "-...": "B",
        "-.-.": "C",
        "-..": "D",
        ".": "E",
        "..-.": "F",
        "--.": "G",
        "....": "H",
        "..": "I",
        ".---": "J",
        "-.-": "K",
        ".-..": "L",
        "--": "M",
        "-.": "N",
        "---": "O",
        ".--.": "P",
        "--.-": "Q",
        ".-.": "R",
        "...": "S",
        "-": "T",
        "..-": "U",
        "...-": "V",
        ".--": "W",
        "-..-": "X",
        "-.--": "Y",
        "--..": "Z",
        "-----": "0",
        ".----": "1",
        "..---": "2",
        "...--": "3",
        "....-": "4",
        ".....": "5",
        "-....": "6",
        "--...": "7",
        "---..": "8",
        "----.": "9",
    }

    try:
        # Split words by '/' or '|' or multiple spaces
        words = re.split(r"[/|]|\s{2,}", data.strip())
        decoded_words = []
        for word in words:
            letters = word.strip().split()
            decoded_word = "".join(morse_dict.get(ch, "?") for ch in letters)
            decoded_words.append(decoded_word)

        decoded = " ".join(decoded_words)
        if "?" not in decoded:
            return DecodingResult("Morse Code", decoded, "high")
    except Exception:
        pass

    return None


ALL_DETECTORS = [
    detect_base64,
    detect_base32,
    detect_hex,
    detect_url_encoding,
    detect_rot13,
    detect_binary,
    detect_octal,
    detect_decimal,
    detect_morse,
]


def detect_encoding(data: str) -> list[DecodingResult]:
    """Try all encoding detectors and return matches.

    Args:
        data: The potentially encoded string.

    Returns:
        A list of DecodingResult objects sorted by confidence.
    """
    results: list[DecodingResult] = []

    for detector in ALL_DETECTORS:
        result = detector(data)
        if result is not None:
            results.append(result)

    # Sort by confidence: high > medium > low
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda r: confidence_order.get(r.confidence, 3))

    return results


def format_results(data: str, results: list[DecodingResult]) -> str:
    """Format detection results as a readable string."""
    lines = [f"Input: {data[:80]}{'...' if len(data) > 80 else ''}"]

    if not results:
        lines.append("  No encoding detected.")
        return "\n".join(lines)

    lines.append(f"  Detected {len(results)} possible encoding(s):")
    for i, r in enumerate(results, 1):
        lines.append(f"    [{i}] {r.encoding} (confidence: {r.confidence})")
        decoded_preview = r.decoded[:100] + ("..." if len(r.decoded) > 100 else "")
        lines.append(f"        Decoded: {decoded_preview}")

    return "\n".join(lines)


def main() -> None:
    """CLI entry point for encoding detection."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    data = " ".join(sys.argv[1:]) if sys.argv[1] != "-a" else " ".join(sys.argv[2:])
    results = detect_encoding(data)
    print(format_results(data, results))


if __name__ == "__main__":
    main()

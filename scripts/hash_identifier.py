"""Hash type identifier for CTF challenges.

Identifies common hash types based on length, character set, and known prefixes.
For EDUCATIONAL and CTF use only.

Usage:
    python hash_identifier.py <hash_string>
    python hash_identifier.py -f <file_with_hashes>
"""

import re
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class HashType:
    name: str
    hashcat_mode: int
    description: str


# Hash patterns ordered by specificity (prefix-based first, then length-based)
PREFIX_PATTERNS: list[tuple[str, HashType]] = [
    (r"^\$2[aby]?\$\d+\$", HashType("bcrypt", 3200, "Blowfish-based adaptive hash")),
    (r"^\$6\$", HashType("sha512crypt", 1800, "SHA-512 based Unix crypt")),
    (r"^\$5\$", HashType("sha256crypt", 7400, "SHA-256 based Unix crypt")),
    (r"^\$1\$", HashType("md5crypt", 500, "MD5 based Unix crypt")),
    (r"^\$apr1\$", HashType("Apache APR1", 1600, "Apache APR1 MD5")),
    (r"^\$P\$", HashType("phpass", 400, "Portable PHP password hash")),
    (r"^\$H\$", HashType("phpass", 400, "Portable PHP password hash")),
    (r"^\$y\$", HashType("yescrypt", 0, "yescrypt password hash")),
    (r"^\$9\$", HashType("Cisco IOS scrypt", 9300, "Cisco IOS type 9 (scrypt)")),
    (r"^\{SHA\}", HashType("LDAP SHA", 101, "LDAP SHA1 base64")),
    (r"^\{SSHA\}", HashType("LDAP SSHA", 111, "LDAP salted SHA1 base64")),
]

LENGTH_PATTERNS: list[tuple[int, str, list[HashType]]] = [
    (32, r"^[a-fA-F0-9]{32}$", [
        HashType("MD5", 0, "128-bit Message Digest"),
        HashType("NTLM", 1000, "Windows NT LAN Manager"),
        HashType("MD4", 900, "128-bit Message Digest 4"),
    ]),
    (40, r"^[a-fA-F0-9]{40}$", [
        HashType("SHA-1", 100, "160-bit Secure Hash Algorithm 1"),
        HashType("MySQL 4.1+", 300, "MySQL 4.1 and above"),
    ]),
    (56, r"^[a-fA-F0-9]{56}$", [
        HashType("SHA-224", 1300, "224-bit SHA-2 family"),
    ]),
    (64, r"^[a-fA-F0-9]{64}$", [
        HashType("SHA-256", 1400, "256-bit SHA-2 family"),
        HashType("SHA3-256", 17400, "256-bit SHA-3 family"),
        HashType("Keccak-256", 17800, "Keccak 256-bit"),
    ]),
    (96, r"^[a-fA-F0-9]{96}$", [
        HashType("SHA-384", 10800, "384-bit SHA-2 family"),
    ]),
    (128, r"^[a-fA-F0-9]{128}$", [
        HashType("SHA-512", 1700, "512-bit SHA-2 family"),
        HashType("SHA3-512", 17600, "512-bit SHA-3 family"),
        HashType("Whirlpool", 6100, "512-bit Whirlpool hash"),
    ]),
]


def identify_hash(hash_string: str) -> list[HashType]:
    """Identify possible hash types from a hash string.

    Args:
        hash_string: The hash string to identify.

    Returns:
        A list of possible HashType matches, ordered by likelihood.
    """
    hash_string = hash_string.strip()
    results: list[HashType] = []

    # Check prefix-based patterns first
    for pattern, hash_type in PREFIX_PATTERNS:
        if re.match(pattern, hash_string):
            results.append(hash_type)

    if results:
        return results

    # Check length-based patterns
    for _length, pattern, hash_types in LENGTH_PATTERNS:
        if re.match(pattern, hash_string):
            results.extend(hash_types)

    # Check for Base64-encoded hashes (common in web challenges)
    if re.match(r"^[A-Za-z0-9+/]+=*$", hash_string) and not results:
        if len(hash_string) == 24:
            results.append(HashType("Base64 (MD5)", 0, "Base64-encoded 128-bit hash"))
        elif len(hash_string) == 28:
            results.append(HashType("Base64 (SHA-1)", 100, "Base64-encoded 160-bit hash"))
        elif len(hash_string) == 44:
            results.append(HashType("Base64 (SHA-256)", 1400, "Base64-encoded 256-bit hash"))

    return results


def format_results(hash_string: str, results: list[HashType]) -> str:
    """Format identification results as a readable string."""
    lines = [f"Hash: {hash_string}"]

    if not results:
        lines.append("  No matching hash type found.")
        return "\n".join(lines)

    lines.append(f"  Possible types ({len(results)} match{'es' if len(results) != 1 else ''}):")
    for i, ht in enumerate(results, 1):
        mode_str = f"hashcat -m {ht.hashcat_mode}" if ht.hashcat_mode > 0 else "N/A"
        lines.append(f"    [{i}] {ht.name} ({ht.description})")
        lines.append(f"        Hashcat mode: {mode_str}")

    return "\n".join(lines)


def main() -> None:
    """CLI entry point for hash identification."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "-f" and len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            hashes = [line.strip() for line in f if line.strip()]
    else:
        hashes = [sys.argv[1]]

    for hash_string in hashes:
        results = identify_hash(hash_string)
        print(format_results(hash_string, results))
        print()


if __name__ == "__main__":
    main()

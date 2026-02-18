# CTF - Capture The Flag Solutions & Writeups

A personal collection of CTF challenge solutions, writeups, and utility scripts for learning cybersecurity concepts.

## Platforms

| Platform | URL | Challenges Solved |
|----------|-----|-------------------|
| [TryHackMe](https://tryhackme.com) | tryhackme.com | 5 |
| [HackTheBox](https://www.hackthebox.com/) | hackthebox.com | 0 |
| [PicoCTF](https://picoctf.org/) | picoctf.org | 0 |
| [Offsec](https://www.offsec.com) | offsec.com | 0 |

## Category Breakdown

| Category | Solved | Status |
|----------|--------|--------|
| Crypto | 3 | Active |
| Web | 1 | Active |
| Forensics | 1 | Active |
| Pwn | 0 | Planned |
| Reverse | 0 | Planned |
| Misc | 0 | Planned |

## Repository Structure

```
CTF/
├── challenges/               # Organized writeups by platform and category
│   ├── hackthebox/
│   │   ├── crypto/
│   │   ├── web/
│   │   ├── forensics/
│   │   └── pwn/
│   ├── tryhackme/
│   │   ├── crypto/           # Cryptography Basics, Hashing Basics, Public Key Crypto
│   │   ├── web/              # Metasploit Intro
│   │   └── forensics/        # Tcpdump
│   └── picoctf/
├── templates/                # Writeup templates
│   ├── writeup-template.md   # General challenge writeup template
│   └── .template             # TryHackMe room walkthrough template
├── scripts/                  # Reusable CTF utility scripts
│   ├── hash_identifier.py    # Identify hash types (MD5, SHA, bcrypt, etc.)
│   ├── encoding_detector.py  # Detect encodings (Base64, hex, ROT13, etc.)
│   ├── port_scanner.py       # Simple TCP port scanner
│   └── xss_payloads.py       # XSS test payload collection
├── tests/                    # Pytest tests for utility scripts
├── docs/                     # Reference documentation
│   └── tools-reference.md    # CTF tools cheat sheets
├── PROGRESS.md               # Challenge progress tracker
└── .github/workflows/ci.yml  # CI pipeline (lint, test, notebook validation)
```

## Completed Challenges

### TryHackMe - Crypto

| Challenge | Difficulty | Topics | Writeup |
|-----------|------------|--------|---------|
| [Cryptography Basics](https://tryhackme.com/room/cryptographybasics) | Easy | XOR, modulo, Caesar cipher | [Writeup](challenges/tryhackme/crypto/cryptographybasics/cryptographybasics.md) |
| [Hashing Basics](https://tryhackme.com/room/hashingbasics) | Easy | MD5, SHA, hashcat, rainbow tables | [Notebook](challenges/tryhackme/crypto/hashingbasics.ipynb) |
| [Public Key Crypto](https://tryhackme.com/room/publickeycrypto) | Easy | RSA, Diffie-Hellman, GPG, SSH | [Writeup](challenges/tryhackme/crypto/publickeycrypto/publickeycrypto.md) |

### TryHackMe - Web

| Challenge | Difficulty | Topics | Writeup |
|-----------|------------|--------|---------|
| [Metasploit Intro](https://tryhackme.com/room/metasploitintro) | Easy | Metasploit framework, exploits, payloads | [Writeup](challenges/tryhackme/web/metasploitintro.md) |

### TryHackMe - Forensics

| Challenge | Difficulty | Topics | Writeup |
|-----------|------------|--------|---------|
| [Tcpdump](https://tryhackme.com/room/tcpdump) | Easy | Packet analysis, ARP, DNS, TCP flags | [Writeup](challenges/tryhackme/forensics/tcpdump.md) |

## Utility Scripts

Reusable Python scripts for common CTF tasks. All scripts include help text via `--help`.

```bash
# Identify a hash type
python scripts/hash_identifier.py "5d41402abc4b2a76b9719d911017c592"

# Detect encoding
python scripts/encoding_detector.py "SGVsbG8gV29ybGQ="

# Scan ports (only scan targets you have permission to test)
python scripts/port_scanner.py 10.10.10.1 --ports 1-1024

# List XSS payloads by category
python scripts/xss_payloads.py basic
```

## Tools Reference

See [docs/tools-reference.md](docs/tools-reference.md) for a comprehensive cheat sheet covering:

- **Crypto:** hashcat, John the Ripper, CyberChef, RsaCtfTool
- **Web:** Burp Suite, SQLMap, gobuster, nikto
- **Forensics:** Autopsy, Volatility, binwalk, Wireshark
- **Pwn:** GDB (pwndbg/GEF), pwntools, ROPgadget
- **Reverse:** Ghidra, radare2, IDA Free

## Getting Started

### Prerequisites

- Python 3.11+
- [Kali Linux](https://www.kali.org/downloads/) (recommended) or any Linux distro
- [VirtualBox](https://www.virtualbox.org/) for lab environments

### Setup

```bash
# Clone the repo
git clone https://github.com/PietjePuh/CTF.git
cd CTF

# Install dev dependencies (for running tests)
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Lint scripts
ruff check scripts/ tests/
```

### Kali Linux Setup

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install openvpn3   # For TryHackMe VPN
msfupdate                    # Update Metasploit
```

See [TryHackMe Attacker Box Setup](https://tryhackme.com/room/kali) for more details.

## Contributing

This is a personal learning repository, but suggestions and corrections are welcome. Feel free to open an issue or PR.

## Disclaimer

All scripts, payloads, and techniques in this repository are intended for **educational purposes and authorized CTF competitions only**. Never use these tools against systems without explicit written permission. Unauthorized access to computer systems is illegal.

## Progress

See [PROGRESS.md](PROGRESS.md) for a detailed tracking dashboard of solved challenges, goals, and statistics.

## Links

- [TryHackMe](https://tryhackme.com)
- [HackTheBox](https://www.hackthebox.com/)
- [PicoCTF](https://picoctf.org/)
- [Offsec](https://www.offsec.com)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

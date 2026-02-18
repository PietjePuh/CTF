# CTF Tools Reference

A curated reference of tools commonly used in Capture The Flag competitions, organized by category.

---

## Crypto

Tools for cryptographic analysis, hash cracking, and cipher breaking.

### hashcat

GPU-accelerated password recovery tool supporting 300+ hash types.

```bash
# Installation
sudo apt install hashcat

# Common usage
hashcat -m 0 -a 0 hash.txt wordlist.txt        # MD5 dictionary attack
hashcat -m 1400 -a 0 hash.txt wordlist.txt      # SHA-256 dictionary attack
hashcat -m 3200 -a 0 hash.txt wordlist.txt      # bcrypt dictionary attack
hashcat -m 1800 -a 0 hash.txt wordlist.txt      # sha512crypt ($6$)
hashcat -m 1000 -a 0 hash.txt wordlist.txt      # NTLM

# Show cracked results
hashcat -m 0 hash.txt --show

# Brute force with mask
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a         # 6-char all characters
```

**Cheat Sheet:**
| Mode | Hash Type |
|------|-----------|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA-256 |
| 1700 | SHA-512 |
| 1800 | sha512crypt ($6$) |
| 3200 | bcrypt ($2*$) |
| 1000 | NTLM |
| 2410 | Cisco-ASA MD5 |

Reference: [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

### John the Ripper

Versatile password cracker with format auto-detection.

```bash
# Installation
sudo apt install john

# Crack a hash file
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked passwords
john hash.txt --show

# Specific format
john --format=raw-md5 hash.txt --wordlist=rockyou.txt

# Crack SSH private key passphrase
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=rockyou.txt

# Crack GPG key passphrase
gpg2john private.key > gpg.hash
john gpg.hash --wordlist=rockyou.txt

# Crack ZIP password
zip2john protected.zip > zip.hash
john zip.hash --wordlist=rockyou.txt
```

### CyberChef

Browser-based data transformation tool ("The Cyber Swiss Army Knife").

```
URL: https://gchq.github.io/CyberChef/
```

**Common Recipes:**
- Base64 Decode/Encode
- ROT13
- XOR with key
- From Hex / To Hex
- URL Decode
- Magic (auto-detect encoding)
- AES Decrypt
- RSA operations

### Python Crypto Libraries

```bash
pip install pycryptodome gmpy2 sympy
```

```python
# RSA example
from Crypto.PublicKey import RSA
from gmpy2 import iroot, invert

# Factor n, compute d, decrypt
phi = (p - 1) * (q - 1)
d = int(invert(e, phi))
m = pow(c, d, n)
print(bytes.fromhex(hex(m)[2:]))
```

### RsaCtfTool

Automated RSA attack tool for CTF challenges.

```bash
# Installation
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool && pip install -r requirements.txt

# Usage
python3 RsaCtfTool.py --publickey public.pem --uncipherfile cipher.txt
python3 RsaCtfTool.py -n <N> -e <e> --uncipher <c>
```

---

## Web

Tools for web application testing, injection, and enumeration.

### Burp Suite

Intercepting proxy for web application security testing.

```bash
# Installation (Community Edition)
# Download from https://portswigger.net/burp/communitydownload

# Key features:
# - Proxy: Intercept and modify HTTP/HTTPS requests
# - Repeater: Manually modify and resend requests
# - Intruder: Automated customized attacks
# - Decoder: Transform data between formats
# - Comparer: Visual diff of responses
```

**Cheat Sheet:**
| Action | Shortcut |
|--------|----------|
| Send to Repeater | Ctrl+R |
| Send to Intruder | Ctrl+I |
| Forward request | Ctrl+F |
| Toggle intercept | Ctrl+T |

### SQLMap

Automated SQL injection detection and exploitation.

```bash
# Installation
sudo apt install sqlmap

# Basic usage
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --dbs

# With cookie
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123" --dbs

# Tamper scripts for WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment --dbs
```

### dirb / gobuster / feroxbuster

Directory and file brute-forcing tools.

```bash
# dirb
sudo apt install dirb
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# gobuster
sudo apt install gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt

# feroxbuster (faster, recursive)
sudo apt install feroxbuster
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### nikto

Web server vulnerability scanner.

```bash
sudo apt install nikto
nikto -h http://target.com
nikto -h http://target.com -p 8080
```

### curl and wget

Command-line HTTP clients for manual testing.

```bash
# GET request
curl -v http://target.com/api/endpoint

# POST with data
curl -X POST http://target.com/login -d "user=admin&pass=test"

# Custom headers
curl -H "Authorization: Bearer token123" http://target.com/api

# Follow redirects
curl -L http://target.com/redirect

# Save cookies
curl -c cookies.txt -b cookies.txt http://target.com
```

---

## Forensics

Tools for digital forensics, memory analysis, and file carving.

### Autopsy

GUI-based digital forensics platform.

```bash
# Installation
sudo apt install autopsy

# Launch
autopsy
# Navigate to http://localhost:9999/autopsy in browser
```

**Key Features:**
- Disk image analysis (E01, raw, VHD)
- File recovery and carving
- Timeline analysis
- Keyword search
- Hash filtering

### Volatility

Memory forensics framework for analyzing RAM dumps.

```bash
# Installation (Volatility 3)
pip install volatility3

# Identify OS profile
vol -f memory.dmp windows.info

# List processes
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree

# Network connections
vol -f memory.dmp windows.netstat

# Command history
vol -f memory.dmp windows.cmdline

# Dump a process
vol -f memory.dmp windows.memmap --pid 1234 --dump

# Registry hives
vol -f memory.dmp windows.registry.hivelist
```

### binwalk

Firmware analysis and file extraction tool.

```bash
# Installation
sudo apt install binwalk

# Scan for embedded files
binwalk firmware.bin

# Extract embedded files
binwalk -e firmware.bin

# Recursive extraction
binwalk -eM firmware.bin

# Entropy analysis (detect encryption/compression)
binwalk -E firmware.bin
```

### Steganography Tools

```bash
# steghide - hide/extract data in images
sudo apt install steghide
steghide extract -sf image.jpg
steghide extract -sf image.jpg -p password

# stegseek - fast steghide brute-force
# https://github.com/RickdeJager/stegseek
stegseek image.jpg wordlist.txt

# exiftool - metadata extraction
sudo apt install exiftool
exiftool image.jpg

# strings - extract readable strings from binary
strings -n 8 suspicious_file

# xxd - hex dump
xxd file.bin | head -50

# file - identify file type
file unknown_file
```

### Wireshark / tshark

Network protocol analyzer.

```bash
# Installation
sudo apt install wireshark tshark

# Read pcap file
tshark -r capture.pcap

# Filter by protocol
tshark -r capture.pcap -Y "http"
tshark -r capture.pcap -Y "dns"

# Extract HTTP objects
tshark -r capture.pcap --export-objects "http,output_dir"

# Display filter examples
tshark -r capture.pcap -Y "ip.addr == 192.168.1.1"
tshark -r capture.pcap -Y "tcp.port == 443"
```

---

## Pwn (Binary Exploitation)

Tools for buffer overflows, ROP chains, and binary exploitation.

### GDB (with pwndbg/GEF)

Enhanced debugging for exploit development.

```bash
# Installation
sudo apt install gdb

# Install pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# OR install GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Common commands
gdb ./binary
run                          # Run the program
break main                   # Set breakpoint
break *0x08048456            # Break at address
info registers               # Show registers
x/20x $esp                   # Examine stack (20 hex words)
x/s 0x08048500               # Examine as string
pattern create 200           # Create cyclic pattern
pattern offset 0x41414141    # Find offset
checksec                     # Check binary protections
vmmap                        # Memory layout
```

### pwntools

Python library for exploit development.

```bash
pip install pwntools
```

```python
from pwn import *

# Connect to remote
r = remote('target.com', 1337)

# Local binary
r = process('./binary')

# Create payload
payload = b'A' * 64           # Buffer overflow padding
payload += p32(0xdeadbeef)    # Return address (32-bit)
payload += p64(0xdeadbeef)    # Return address (64-bit)

# Send and receive
r.sendline(payload)
r.recvuntil(b'flag{')
flag = r.recvline()

# Shellcraft
shellcode = asm(shellcraft.sh())

# ELF analysis
elf = ELF('./binary')
print(hex(elf.symbols['win']))
print(hex(elf.got['puts']))
```

### ROPgadget

Find ROP gadgets in binaries.

```bash
# Installation
pip install ROPgadget

# Find gadgets
ROPgadget --binary ./vuln_binary
ROPgadget --binary ./vuln_binary --ropchain
ROPgadget --binary ./vuln_binary | grep "pop rdi"
```

### checksec

Check binary security protections.

```bash
# Using pwntools
checksec ./binary

# Output explains:
# RELRO       - Relocation Read-Only (Full/Partial/No)
# Stack       - Stack canary (Canary found / No canary found)
# NX          - Non-executable stack (NX enabled / NX disabled)
# PIE         - Position Independent Executable (PIE enabled / No PIE)
# ASLR        - Address Space Layout Randomization (check /proc/sys/kernel/randomize_va_space)
```

---

## Reverse Engineering

Tools for analyzing binaries and understanding program behavior.

### Ghidra

NSA's open-source reverse engineering suite.

```bash
# Installation
# Download from https://ghidra-sre.org/
# Extract and run:
./ghidraRun

# Key features:
# - Decompiler (C-like pseudocode)
# - Disassembler
# - Graph view
# - Scripting (Java/Python)
# - Collaborative analysis
```

**Cheat Sheet:**
| Action | Shortcut |
|--------|----------|
| Decompile function | Select function in listing |
| Rename variable | L |
| Set type | Ctrl+L |
| Cross references | Ctrl+Shift+F |
| Search strings | Search > For Strings |
| Patch bytes | Ctrl+Shift+G |

### radare2

Command-line reverse engineering framework.

```bash
# Installation
sudo apt install radare2

# Open binary
r2 ./binary

# Analysis
aaa                  # Full analysis
afl                  # List functions
pdf @main            # Disassemble main
s main               # Seek to main

# Visual mode
V                    # Enter visual mode
VV                   # Graph view
p                    # Cycle through views

# Strings
iz                   # Strings in data section
izz                  # All strings

# Search
/ flag{              # Search for string
/x 9090              # Search for hex bytes
```

### IDA Free

Industry-standard disassembler (free version available).

```
Download: https://hex-rays.com/ida-free/
```

**Key Features:**
- Interactive disassembly
- Cross-references
- Function recognition (FLIRT signatures)
- Scripting via IDAPython
- Graph view

### ltrace / strace

Trace library and system calls.

```bash
# Library call tracing
ltrace ./binary

# System call tracing
strace ./binary
strace -e trace=open,read,write ./binary

# Follow child processes
strace -f ./binary
```

---

## General / Misc

### nmap

Network mapper and port scanner.

```bash
# Quick scan
nmap -sC -sV target.com

# Full port scan
nmap -p- target.com

# UDP scan
nmap -sU target.com

# Aggressive scan
nmap -A target.com

# Script scan
nmap --script=vuln target.com
```

### Wordlists

```bash
# rockyou.txt (most common)
/usr/share/wordlists/rockyou.txt

# SecLists (comprehensive collection)
sudo apt install seclists
/usr/share/seclists/

# Key wordlists:
# /usr/share/seclists/Passwords/Common-Credentials/
# /usr/share/seclists/Discovery/Web-Content/
# /usr/share/seclists/Fuzzing/
```

### CrackStation / Hashes.com

Online hash lookup services:
- [CrackStation](https://crackstation.net/)
- [Hashes.com](https://hashes.com/en/decrypt/hash)

---

## Quick Installation (Kali Linux)

Most tools come pre-installed on Kali Linux. For a minimal setup:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
  hashcat john \
  sqlmap dirb gobuster nikto \
  binwalk steghide exiftool wireshark tshark \
  gdb radare2 \
  nmap \
  python3-pip

pip install pwntools volatility3 ROPgadget
```

---

## References

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be exploited
- [HackTricks](https://book.hacktricks.xyz/) - Pentesting methodology wiki
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Payload collection
- [CyberChef](https://gchq.github.io/CyberChef/) - Data transformation tool
- [Exploit-DB](https://www.exploit-db.com/) - Public exploit database
- [RevShells](https://www.revshells.com/) - Reverse shell generator

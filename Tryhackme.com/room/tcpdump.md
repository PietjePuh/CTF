---

# 🔎 TryHackMe Walkthrough – Tcpdump Traffic Analysis

> **Author:** PietjePuh  
> **Date:** 2025-06-08  
> **Room link:** [https://tryhackme.com/room/tcpdump](https://tryhackme.com/room/tcpdump)

---

## 🎯 Objectives

- Understand and apply basic Tcpdump commands
- Analyze a `.pcap` file using filters
- Identify traffic patterns using packet size and protocol
- Build familiarity with ARP, DNS, ICMP, and TCP reset flags

---

## 🛠️ Setup

| Component        | Value                         |
|------------------|-------------------------------|
| OS               | Kali Linux (THM environment)  |
| Tools            | `tcpdump`, `grep`, `wc`       |
| File             | `traffic.pcap`                |
| Difficulty       | 🟢 Easy                        |

---

## 🧪 Analysis Steps

### Q1. 🔍 How many packets use the ICMP protocol?
```bash
tcpdump -r traffic.pcap icmp | wc -l
```

### Q2. 🧭 What is the IP address of the host that requested the MAC address of `192.168.124.137`?
```bash
tcpdump -r traffic.pcap arp -nn
```
**Answer:** `192.168.124.148`

### Q3. 🌐 What hostname (subdomain) appears in the first DNS query?
```bash
tcpdump -r traffic.pcap port 53
```
**Answer:** `mirrors.rockylinux.org`

### Q4. 🔁 How many packets have only the TCP Reset (RST) flag set?
```bash
tcpdump -r traffic.pcap "tcp[tcpflags] == tcp-rst" | wc -l
```
**Answer:** `57`

### Q5. 🚚 What is the IP address of the host that sent packets larger than 15000 bytes?
```bash
tcpdump -nn -r traffic.pcap 'greater 15000'
```
**Answer:** `185.117.80.53`

### Q6. 🧱 What is the MAC address of the host that sent the ARP request?
```bash
tcpdump -nn -r traffic.pcap -e | grep ARP
```
**Answer:** `52:54:00:7c:d3:5b`

---

## 💬 Useful Tcpdump Commands

```bash
# Capture from interface
sudo tcpdump -i eth0
sudo tcpdump -i any

# Save output
sudo tcpdump -w capture.pcap

# Read from file
tcpdump -r capture.pcap

# Filter by host
tcpdump host 192.168.1.1

# Filter by port
tcpdump port 80
tcpdump port 53

# Filter by protocol
tcpdump icmp
tcpdump arp
```

### Common Tcpdump Flags

| Flag | Description |
|------|-------------|
| `-q` | Quick output; print brief packet information |
| `-e` | Print the link-level (Ethernet) header |
| `-A` | Show packet data in ASCII |
| `-xx`| Show packet data in hexadecimal format only |
| `-X` | Show packet headers and data in hex and ASCII |

---

## 🎓 Learning Summary

- Learned how to interpret ARP, DNS, and ICMP queries from raw traffic
- Applied Tcpdump filters to isolate specific traffic patterns
- Practiced parsing `.pcap` files with `tcpdump`, a CLI alternative to Wireshark
- Used `man` pages to explore additional syntax: `man tcpdump`, `man pcap-filter` `man wc`

---

## 🔗 References & Tools

- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [Official Tcpdump Docs](https://www.tcpdump.org/)
- [TryHackMe Room - Tcpdump](https://tryhackme.com/room/tcpdump)
- [InfoSec Writeups](https://infosecwriteups.com/)
- [WinDump for Windows](https://www.winpcap.org/windump/)

---

## 📢 Want more?

Follow me on:
- GitHub: [github.com/PietjePuh](https://github.com/PietjePuh)
- LinkedIn: [linkedin.com/in/tim-van-maurik-77060740](https://www.linkedin.com/in/tim-van-maurik-77060740/)

*#TryHackMe #Tcpdump #NetworkForensics #CTF #PacketAnalysis #LinuxSecurity*

---

> *This write-up is part of my continuous learning journey through TryHackMe. Each post is designed to document findings, boost retention, and help others in the cybersecurity community.*

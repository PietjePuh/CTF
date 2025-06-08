---
title: "TryHackMe Walkthrough – Tcpdump Traffic Analysis"
author: "PietjePuh"
date: 2025-06-08
Room link: [https://tryhackme.com/room/tcpdump](https://tryhackme.com/room/tcpdump)
YouTube reference: [Tcpdump Tutorial – Network Packet Analysis](https://www.youtube.com/watch?v=7hDvuuKN66U&t)
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

## 🧪 Tasks & Questions

### 🧪 Task 1: Tcpdump Essentials

#### Q0. 📚 What is the name of the library that is associated with tcpdump?

<details>
<summary>💡 Click to reveal explanation</summary>

> Tcpdump relies on a packet capture library called **libpcap** to capture packets from network interfaces. It provides a portable framework for low-level network monitoring.

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `libpcap`

</details>

#### Q1. 🧠 What option can you add to your command to display addresses only in numeric format?

<details>
<summary>💡 Click to reveal explanation</summary>

> By default, `tcpdump` attempts to resolve IP addresses and ports into hostnames and service names, which can delay output and clutter the result. Using `-n` disables this behavior, improving readability and speed.

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `-n`

</details>

---

### 🧪 Task 2: Basic Packet Capture

_This task introduced the use of flags like `-i` for interfaces, `-c` for packet counts, `-w` for saving, `-r` for reading, and `-v` for verbosity._

#### Q1. 🧾 What is the standard required for handling credit card information?

<details>
<summary>💡 Click to reveal explanation</summary>

> PCI DSS (Payment Card Industry Data Security Standard) is a widely accepted standard that ensures organizations that process, store, or transmit credit card information maintain a secure environment.

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `PCI DSS`

</details>

---

### 🧪 Task 3: Filtering Expressions

#### Q1. 🔍 How many packets in traffic.pcap use the ICMP protocol?

<details>
<summary>💡 Click to reveal explanation</summary>

> ICMP is commonly used for diagnostics like `ping`. You can count these packets with `tcpdump -r traffic.pcap icmp | wc -l`.

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `26`

</details>

#### Q2. 🧭 What is the IP address of the host that asked for the MAC address of 192.168.124.137?

<details>
<summary>💡 Click to reveal explanation</summary>

> Hint: Filter by ARP using `tcpdump -r traffic.pcap arp -nn | grep 192.168.124.137`

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `192.168.124.148`

</details>

#### Q3. 🌐 What hostname (subdomain) appears in the first DNS query?

<details>
<summary>💡 Click to reveal explanation</summary>

> DNS queries reveal which domain a system is trying to reach. Use `tcpdump -r traffic.pcap port 53` to extract this.

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `mirrors.rockylinux.org`

</details>

...

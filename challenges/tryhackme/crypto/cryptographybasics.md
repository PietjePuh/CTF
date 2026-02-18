---
title: "TryHackMe Walkthrough – Cryptography Basics"
author: "PietjePuh"
date: 2025-06-08
Room link: [https://tryhackme.com/room/cryptographybasics](https://tryhackme.com/room/cryptographybasics)
---

## 🎯 Objectives

- Learn foundational cryptography concepts
- Understand XOR, Caesar Cipher, Base64, and hashing
- Apply encoding/decoding to solve challenges
- Reinforce theory with real-world tasks

---

## 🛠️ Setup

| Component        | Value                         |
|------------------|-------------------------------|
| Platform         | TryHackMe                     |
| Tools            | CyberChef, Terminal, Python   |
| Difficulty       | 🟢 Easy                        |

---

## 🧪 Task 1: Introduction

> This room introduces the basics of cryptography – the art of secure communication. Each task includes a short explanation and hands-on decryption activity. Let’s break the ciphers!

_No questions in this task._

---

## 🧪 Task 2: XOR Operation

### 📌 Concept
XOR (Exclusive OR) compares bits:

| A | B | A ⊕ B |
|---|---|-------|
| 0 | 0 |   0   |
| 0 | 1 |   1   |
| 1 | 0 |   1   |
| 1 | 1 |   0   |

Used in symmetric encryption like the One-Time Pad. 

---

#### Q1. 🧮 What is `1001 ⊕ 1010`?

<details>
<summary>💡 Click to reveal explanation</summary>

> Perform bitwise XOR:
> 1001 ⊕ 1010 = 0011 → `3`

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `3`

</details>

---

## 🧪 Task 3: Modulo Operation

### 📌 Concept
Modulo (`%`) gives the remainder after division. Crucial in cyclic operations like Caesar Cipher:

Example: `118613842 % 9091` gives remainder → result = `3565`

#### Q1. 🔢 What’s `118613842 % 9091`?

<details>
<summary>💡 Click to reveal explanation</summary>

> 118613842 ÷ 9091 = 13053 R **3565**

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `3565`

</details>

---

## 🧪 Task 4: Caesar Cipher

### 📌 Concept
Shift each letter in the alphabet by a fixed key.

Example with key 3: `A → D`, `B → E`, ...

Decrypt: `XRPCTCRGNEI` with shift 3

#### What’s the plaintext of `XRPCTCRGNEI` (Caesar +3)?

<details>
<summary>💡 Click to reveal explanation</summary>

> Shift each letter **backwards** by 3:
> - X → U
> - R → O
> - P → M
> - C → Z
> → Result: `UMZZAZODKBF`

</details>

<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `UMZZAZODKBF`

</details>

---

## 🔚 Conclusion

This room introduces fundamental concepts in cryptography using XOR, modulo, Caesar ciphers, and encoding tricks. A strong understanding of these operations is critical before diving into more advanced encryption like RSA or AES.

For deeper study:
- [CyberChef](https://gchq.github.io/CyberChef/) – powerful web tool
- [Cryptopals Challenges](https://cryptopals.com/) – progressive cryptography tasks
- [Caesar cipher - Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [XOR cipher - Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
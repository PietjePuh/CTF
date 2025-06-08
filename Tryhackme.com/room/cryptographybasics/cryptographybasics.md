---
title: "Cryptography Basics – TryHackMe Walkthrough"
author: "PietjePuh"
date: 2025-06-08
---

# 🔐 TryHackMe Walkthrough – Cryptography Basics

> **Author:** PietjePuh  
> **Date:** 2025-06-08  
> **Room link:** [https://tryhackme.com/room/cryptographybasics](https://tryhackme.com/room/cryptographybasics)

---

## 🎯 Objectives

- Understand XOR and modulo operations
- Apply XOR to binary strings
- Understand the reversible properties of XOR in encryption
- Use Python to calculate modulo results for large numbers

---

## 📘 Key Concepts

### 🔁 XOR Operation
The XOR (exclusive OR) operation returns 1 if the bits are different, and 0 if they are the same.

| A | B | A ⊕ B |
|---|---|--------|
| 0 | 0 | 0      |
| 0 | 1 | 1      |
| 1 | 0 | 1      |
| 1 | 1 | 0      |

#### Properties:
- A ⊕ A = 0
- A ⊕ 0 = A
- Commutative: A ⊕ B = B ⊕ A
- Associative: (A ⊕ B) ⊕ C = A ⊕ (B ⊕ C)

#### 🔐 Used in Symmetric Encryption
Let `P` be plaintext, `K` be the key, and `C` the ciphertext.
- C = P ⊕ K
- P = C ⊕ K

### 💻 Python Example – XOR
```python
def xor_binary(bin1, bin2):
    int1 = int(bin1, 2)
    int2 = int(bin2, 2)
    xor_result = int1 ^ int2
    max_len = max(len(bin1), len(bin2))
    return format(xor_result, f'0{max_len}b')

bin1 = "1001"
bin2 = "1010"
result = xor_binary(bin1, bin2)
print(f"{bin1} ⊕ {bin2} = {result}")
```
<details>
<summary>✅ Click to reveal answer</summary>

**Answer:** `1001 ⊕ 1010 = 0011`

> 💡 **Explanation:** XOR is used here to demonstrate how a simple symmetric encryption scheme works. The XOR of two binary strings flips bits where the key has 1s. This property makes XOR valuable for reversible encryption where applying the same key twice restores the original value.

</details>

---

### ➗ Modulo Operation
The modulo operator returns the remainder of a division.

#### Examples:
- 25 % 5 = 0  → 25 = 5 × 5 + 0
- 23 % 6 = 5  → 23 = 3 × 6 + 5
- 23 % 7 = 2  → 23 = 3 × 7 + 2

📌 The result is always between 0 and (divisor - 1).

### 💻 Python Example – Modulo
```python
print(118613842 % 9091)  # Output: 3565
print(60 % 12)           # Output: 0
```
<details>
<summary>✅ Click to reveal answer</summary>

**Answer 1:** `118613842 % 9091 = 3565`  
**Answer 2:** `60 % 12 = 0`

> 💡 **Explanation:** Modulo is used to find the remainder after division and is essential in cryptography, especially for cyclic structures like key spaces and hash functions. For example, in modular arithmetic, many cryptographic operations rely on calculating with remainders rather than exact division.

</details>

---

## ✅ Summary

| Concept        | Description                                |
|----------------|--------------------------------------------|
| XOR            | Bitwise operation used in cryptography     |
| Modulo         | Arithmetic remainder useful in crypto math |
| Python use     | Helps automate large number calculations   |

---

## 🔗 References
- [TryHackMe Room – Cryptography Basics](https://tryhackme.com/room/cryptographybasics){:target="_blank"}
- [Python int() Docs](https://docs.python.org/3/library/functions.html#int){:target="_blank"}
- [WolframAlpha](https://www.wolframalpha.com/){:target="_blank"}

---

> *This post is part of a learning series on cybersecurity topics via TryHackMe. Feel free to fork, adapt, or build upon these examples.*

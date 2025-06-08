### Task 1: Introduction

Consider the following scenario from everyday life. Let’s say you are meeting a business partner over coffee and discussing somewhat confidential business plans. Let’s break down the meeting from the security perspective.

You can see and hear the other person. Consequently, it is easy to be sure of their identity. That’s **authentication**, i.e., you are confirming the identity of who you are talking with.  
You can also confirm that what you are “hearing” is coming from your business partner. You can tell what words and sentences are coming from your business partner and what is coming from others. That’s **authenticity**, i.e., you verify that the message genuinely comes from a specific sender. Moreover, you know that what they are saying is reaching you, and there is no chance of anything changing the other party’s words across the table. That’s **integrity**, i.e., ensuring that the data has not been altered or tampered with.  
Finally, you can pick a seat away from the other customers and keep your voice low so that only your business partner can hear you. That’s **confidentiality**, i.e., only the authorised parties can access the data.

Let’s quickly compare this with correspondence in the cyber realm. When someone sends you a text message, how can you be sure they are who they claim to be? How can you be sure that nothing changed the text as it travelled across various network links? When you are communicating with your business partner over an online messaging platform, you need to be sure of the following:

- **Authentication**: You want to be sure you communicate with the right person, not someone else pretending.  
- **Authenticity**: You can verify that the information comes from the claimed source.  
- **Integrity**: You must ensure that no one changes the data you exchange.  
- **Confidentiality**: You want to prevent an unauthorised party from eavesdropping on your conversations.  

Cryptography can provide solutions to satisfy the above requirements. Private key cryptography (symmetric encryption) mainly protects confidentiality, while public key cryptography (asymmetric encryption) plays a key role in authentication, authenticity, and integrity.

<details>
  <summary>Explanation</summary>

  - **Authentication**: Verifying identity maps to digital signatures and certificate-based logins.  
  - **Authenticity**: Ensured by signing messages with a private key.  
  - **Integrity**: Guaranteed by cryptographic hashes and signatures.  
  - **Confidentiality**: Achieved through encryption algorithms that only allow holders of the correct keys to read the data.  

  This introduction frames why we need asymmetric cryptography for securing communications.
</details>

<details>
  <summary>Key Concepts</summary>

  - **Private Key Cryptography**: Uses a single key for both encryption and decryption, suitable for confidentiality.  
  - **Public Key Cryptography**: Uses a pair of keys (public and private) to enable secure communication, ensuring authentication, authenticity, integrity, and confidentiality.  

  This section sets the stage for understanding the need for public key cryptography.
</details>

# Task 2
Common Use of Asymmetric Encryption
Exchanging keys for symmetric encryption is a widespread use of asymmetric cryptography. Asymmetric encryption is relatively slow compared to symmetric encryption; therefore, we rely on asymmetric encryption to negotiate and agree on symmetric encryption ciphers and keys.

But the question is, how do you agree on a key with the server without transmitting the key for people snooping to see?

Box with a lock

Analogy
Imagine you have a secret code for communicating and instructions for using the secret code. The question is how you can send these instructions to your friend without anyone else being able to read them. The answer is more straightforward than it seems; you could ask your friend for a lock. Only your friend has the key for this lock, and we’ll assume you have an indestructible box you can lock with it.

If you send the instructions in a locked box to your friend, they can unlock it once it reaches them and read the instructions. After that, you can communicate using the secret code without the risk of people snooping.

In this metaphor, the secret code represents a symmetric encryption cipher and key, the lock represents the server’s public key, and the key represents the server’s private key.

Analogy	Cryptographic System
Secret Code	Symmetric Encryption Cipher and Key
Lock	Public Key
Lock’s Key	Private Key
Consequently, you would only need to use asymmetric cryptography once so that it won’t affect the speed, and then you can communicate privately using symmetric encryption.

The Real World
In reality, you need more cryptography to verify that the person you’re talking to is who they say they are. This is achieved using digital signatures and certificates, which we will visit later in this room.

## Answer the questions below
In the analogy presented, what real object is analogous to the public key?
<details>
<summary>✅ Answer:</summary>
The public key is analogous to the lock that only your friend has the key for.   
**Answer: Lock** 
</details>

Task 3RSA
RSA is a public-key encryption algorithm that enables secure data transmission over insecure channels. With an insecure channel, we expect adversaries to eavesdrop on it.

The Math That Makes RSA Secure
RSA is based on the mathematically difficult problem of factoring a large number. Multiplying two large prime numbers is a straightforward operation; however, finding the factors of a huge number takes much more computing power.

It’s simple to multiply two prime numbers together even on paper, say 113 × 127 = 14351. Even for larger prime numbers, it would still be a feasible job, even by hand. Consider the following numeric example:

Prime number 1: 982451653031
Prime number 2: 169743212279
Their product: 982451653031 × 169743212279 = 166764499494295486767649
On the other hand, it’s pretty tricky to determine what two prime numbers multiply together to make 14351 and even more challenging to find the factors of 166764499494295486767649.

In real-world examples, the prime numbers would be much bigger than the ones in this example. A computer can easily factorise 166764499494295486767649; however, it cannot factorise a number with more than 600 digits. And you would agree that the multiplication of the two huge prime numbers, each around 300 digits, would be easier than the factorisation of their product.

Numerical Example
Let’s revisit encryption, decryption, and key usage in asymmetric encryption. The public key is known to all correspondents and is used for encryption, while the private key is protected and used for decryption, as shown in the figure below.

Alice encrypts the message with Bob's public key and Bob decrypts it with his private key.

In the Cryptography Basics room, we explained the modulo operation and said it plays a significant role in cryptography. In the following simplified numerical example, we see the RSA algorithm in action:

Bob chooses two prime numbers: p = 157 and q = 199. He calculates n = p × q = 31243.
With ϕ(n) = n − p − q + 1 = 31243 − 157 − 199 + 1 = 30888, Bob selects e = 163 such that e is relatively prime to ϕ(n); moreover, he selects d = 379, where e × d = 1 mod ϕ(n), i.e., e × d = 163 × 379 = 61777 and 61777 mod 30888 = 1. The public key is (n,e), i.e., (31243,163) and the private key is $(n,d), i.e., (31243,379).
Let’s say that the value they want to encrypt is x = 13, then Alice would calculate and send y = xe mod n = 13163 mod 31243 = 16341.
Bob will decrypt the received value by calculating x = yd mod n = 16341379 mod 31243 = 13. This way, Bob recovers the value that Alice sent.
The proof that the above algorithm works can be found in modular arithmetic and is beyond the scope of this module. It is worth repeating that in this example, we picked a three-digit prime number, while in an actual application, p and q would be at least a 300-digit prime number each.

RSA in CTFs
The math behind RSA comes up relatively often in CTFs, requiring you to calculate variables or break some encryption based on them. Many good articles online explain RSA, and they will give you almost all of the information you need to complete the challenges. One good example of an RSA CTF challenge is the Breaking RSA room.

There are some excellent tools for defeating RSA challenges in CTFs. My favourite is RsaCtfTool, which has worked well for me. I’ve also had some success with rsatool.

You need to know the main variables for RSA in CTFs: p, q, m, n, e, d, and c. As per our numerical example:

p and q are large prime numbers
n is the product of p and q
The public key is n and e
The private key is n and d
m is used to represent the original message, i.e., plaintext
c represents the encrypted text, i.e., ciphertext
Crypto CTF challenges often present you with a set of these values, and you need to break the encryption and decrypt a message to retrieve the flag.

# Question 1
## Knowing that p = 4391 and q = 6659, what is n?

<details>
<summary>💡 Explanation</summary>

To compute **n** in RSA, you multiply the two prime numbers:

\[
n = p \times q = 4391 \times 6659 = 29243869
\]

This value of **n** is used as part of the public and private keys in RSA encryption.

</details>

<details>
<summary>💻 Commands</summary>

```python
# Calculate n using a simple one-liner
python3 -c "print(4391 * 6659)"
```

</details> 

<details> <summary>✅ Answer</summary>
Answer: 29243869

</details>

# Question 2
## Knowing that p = 4391 and q = 6659. What is ϕ(n)?

<details> <summary>💡 Explanation</summary>
To calculate Euler’s totient function (ϕ), use the formula:
ϕ(n) = (p - 1) × (q - 1)
ϕ(n) = (4391 - 1) × (6659 - 1)
ϕ(n) = 4390 × 6658 = 29,192,620
</details>

<details> <summary>✅ Answer</summary>
29192620
<details>

<details>
<summary>💻 Commands</summary>

```python
# phi_calculator.py

# Given prime numbers
p = 4391
q = 6659

# Calculate phi(n)
phi_n = (p - 1) * (q - 1)

# Output the result
print(f"ϕ(n) = ({p} - 1) * ({q} - 1) = {phi_n}")
```

</details> 
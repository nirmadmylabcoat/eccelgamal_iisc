# 🔐 ECC-Based Crypto Demos

This repository includes two elliptic curve cryptography (ECC) based protocols implemented in C using OpenSSL:

- 📌 `eccelgamalot.c` – Simulates an ECC ElGamal-style encryption for Oblivious Transfer
- 📌 `pedersen_commitment.c` – Demonstrates Pedersen commitment scheme over elliptic curves

These demos showcase how modern cryptographic primitives can be securely built on elliptic curves, ensuring privacy, randomness, and computational hardness against adversaries.

---

## 🔍 Files

### 🗂️ `eccelgamalot.c`

Simulates the core cryptographic idea behind 1-out-of-2 **Oblivious Transfer** using ECC ElGamal:

- Generates ephemeral ECC key (sender)
- Receiver creates a **fake public key** (hash-to-point)
- Sender encrypts with this fake key:  
  \[
  C_1 = kG,\quad C_2 = k \cdot \text{PK}_{\text{fake}}
  \]
- Receiver learns nothing without knowledge of `k`

✅ This approach is:
- **Secure** against brute-force since ECC discrete log is hard  
- **Private** because fake keys offer no hint of receiver's choice

---

### 🗂️ `pedersen_commitment.c`

Implements a **Pedersen commitment** over ECC:

- Commits to a value `m` with randomness `r`:
  \[
  C = mG + H'
  \]
  where `H'` is derived by hashing `r` and converting to a valid EC point.
- Later, verifies by recomputing and matching coordinates.

✅ This scheme is:
- **Hiding**: conceals `m` since `r` randomizes the result  
- **Binding**: can't open `C` to a different `m` without solving ECC hardness assumptions

---

## ⚙️ Build & Run Instructions

### 📦 Prerequisites

- OpenSSL development libraries (`libssl-dev`)
- GCC

---

### 🛠️ Compile

```bash
gcc eccelgamalot.c -o ecc_ot -lcrypto
gcc pedersen_commitment.c -o pedersen -lcrypto

# 🔐 Cryptography Algorithms Implementation

> **Project 6 — Cybersecurity Internship | Codec Technologies**

A comprehensive Python implementation of fundamental cryptographic algorithms used in real-world security systems — from AES symmetric encryption to RSA digital signatures.

---

## 📦 Algorithms Implemented

| Algorithm | Type | Key Size | Real-World Use |
|-----------|------|----------|----------------|
| **AES-256-CBC** | Symmetric cipher | 256-bit | File/disk encryption, VPNs |
| **RSA-2048-OAEP** | Asymmetric cipher | 2048-bit | TLS key exchange, HTTPS |
| **RSA-PSS** | Digital signature | 2048-bit | Code signing, certificates |
| **SHA-256/512** | Hash function | N/A | Data integrity, blockchain |
| **HMAC-SHA256** | Keyed hash | Variable | API authentication, JWT |
| **PBKDF2-SHA256** | Key derivation | N/A | Password storage |
| **Hybrid RSA+AES** | Combined | Mixed | TLS 1.2/1.3 protocol |

---

## 🚀 Quick Start

```bash
# Install dependency
pip install cryptography

# Run all demonstrations
python3 crypto_algorithms.py
```

---

## 📁 Module Overview

### `AESCipher` — AES-256-CBC Symmetric Encryption
```python
from crypto_algorithms import AESCipher

# From a password (PBKDF2 key derivation)
aes, salt = AESCipher.from_password("MySecurePassword!")
encrypted = aes.encrypt("Secret message")
decrypted = aes.decrypt(encrypted)

# From a raw 32-byte key
aes = AESCipher(key=os.urandom(32))
```

**How it works:**
- PKCS7 padding aligns plaintext to 16-byte blocks
- Random IV (Initialization Vector) ensures different ciphertext each time
- CBC chaining: each block depends on the previous — prevents pattern analysis

### `RSACipher` — RSA-2048 Asymmetric Encryption
```python
from crypto_algorithms import RSACipher

rsa = RSACipher(key_size=2048)

# Encrypt with public key, decrypt with private key
encrypted = rsa.encrypt("Secret AES key")
decrypted = rsa.decrypt(encrypted)

# Sign with private key, verify with public key
signed  = rsa.sign("Contract document text")
is_valid = rsa.verify(signed)  # True
```

**Security basis:** Integer factorization problem — given `n = p × q`, recovering `p` and `q` is computationally infeasible for large primes.

### `SHAHasher` — Cryptographic Hash Functions
```python
from crypto_algorithms import SHAHasher

# One-way hash
digest = SHAHasher.hash("data", alg='SHA-256')

# HMAC for message authentication
mac    = SHAHasher.hmac_sign("request body", "api-secret")
valid  = SHAHasher.verify_hmac("request body", "api-secret", mac)

# Avalanche effect demo
SHAHasher.avalanche()  # Shows ~50% bit flip from 1 char change
```

### `PasswordSecurity` — PBKDF2 Hashing
```python
from crypto_algorithms import PasswordSecurity

stored  = PasswordSecurity.hash_password("user_password")
is_ok   = PasswordSecurity.verify("user_password", stored)   # True
is_bad  = PasswordSecurity.verify("wrong_password", stored)  # False
```

**Why PBKDF2 over SHA-256?**  
Plain SHA-256: GPU can try **10 billion** hashes/second  
PBKDF2 (100k iterations): GPU can try only **~100,000** passwords/second  
→ Brute-force becomes **100,000×** harder

### `HybridEncryption` — RSA + AES Combined
```python
from crypto_algorithms import HybridEncryption, RSACipher

rsa    = RSACipher(2048)
hybrid = HybridEncryption(rsa)

pkg       = hybrid.encrypt("Large document...")  # AES encrypts data, RSA wraps key
recovered = hybrid.decrypt(pkg)
```

---

## 🔬 Key Concepts Demonstrated

### Avalanche Effect
A single character change causes ~50% of hash output bits to flip:
```
Input:  "Hello, World!"    → SHA256: a591a6d40bf420...
Input:  "Hello, World!!"   → SHA256: 4b2a9d7ca8f9e1...
Bits flipped: 122/256 = 47.7%
```

### Why Salt Passwords?
```
MD5("password123")  → 482c811da5d5...  ← same hash for every user!
PBKDF2(salt1, "password123") → 7f3a91...  ← unique
PBKDF2(salt2, "password123") → c2d8fe...  ← completely different
```

### Hybrid Encryption (How HTTPS Works)
```
Client                          Server
  │                               │
  │──── RSA: send AES key ──────→ │  (asymmetric — no shared secret needed)
  │                               │
  │←──────── AES encrypted ──────→│  (symmetric — fast, unlimited size)
```

---

## 📊 Security Comparison

| Attack | MD5 | SHA-256 | PBKDF2-SHA256 |
|--------|-----|---------|---------------|
| Brute force (GPU) | ~50B/sec | ~10B/sec | ~100K/sec |
| Rainbow tables | ✗ Vulnerable | ✗ Vulnerable | ✓ Salt prevents |
| Collision found? | ✅ Yes (2004) | ❌ No | N/A |
| NIST Recommended | ❌ No | ✅ Yes | ✅ Yes |

---

## 🛡️ Security Best Practices Used

- ✅ **Random IV** per encryption (CBC mode) — prevents ciphertext pattern analysis  
- ✅ **OAEP padding** for RSA — defeats chosen-ciphertext attacks  
- ✅ **PSS padding** for RSA signatures — probabilistic, more secure than PKCS1v15  
- ✅ **Constant-time comparison** (`hmac.compare_digest`) — prevents timing attacks  
- ✅ **Unique salt** per password — defeats rainbow table attacks  
- ✅ **100,000+ PBKDF2 iterations** — NIST SP 800-132 compliant  
- ✅ **No custom crypto** — uses well-audited `cryptography` library  

---

## 📚 References

- [NIST FIPS 197 — AES Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
- [NIST SP 800-131A — Cryptographic Algorithm Transitions](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 8017 — PKCS #1 v2.2: RSA Cryptography](https://www.rfc-editor.org/rfc/rfc8017)


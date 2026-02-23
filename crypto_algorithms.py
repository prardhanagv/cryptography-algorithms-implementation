"""
╔══════════════════════════════════════════════════════════════╗
║          Cryptography Algorithms Implementation              ║
║     AES-256-CBC, RSA-2048, SHA-256/512 & PBKDF2             ║
╚══════════════════════════════════════════════════════════════╝

Project 6: Cryptography Algorithms Implementation
Cybersecurity Internship — Codec Technologies
"""

import os, time, hashlib, hmac, base64
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ── AES-256-CBC ──────────────────────────────────────────────

class AESCipher:
    """AES-256-CBC symmetric encryption with PKCS7 padding."""
    BLOCK_SIZE = 16
    KEY_SIZE   = 32

    def __init__(self, key: bytes = None):
        self.key = key if key else os.urandom(self.KEY_SIZE)

    @classmethod
    def from_password(cls, password: str, salt: bytes = None):
        salt = salt or os.urandom(16)
        key  = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000, 32)
        return cls(key), salt

    def encrypt(self, plaintext: str) -> Dict[str, str]:
        iv     = os.urandom(self.BLOCK_SIZE)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        enc    = cipher.encryptor()
        ct     = enc.update(padded) + enc.finalize()
        return {'algorithm':'AES-256-CBC','iv':base64.b64encode(iv).decode(),'ciphertext':base64.b64encode(ct).decode()}

    def decrypt(self, pkg: Dict) -> str:
        iv     = base64.b64decode(pkg['iv'])
        ct     = base64.b64decode(pkg['ciphertext'])
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        dec    = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unp    = sym_padding.PKCS7(128).unpadder()
        return (unp.update(padded) + unp.finalize()).decode()

    @property
    def key_hex(self): return self.key.hex()


# ── RSA-2048 ─────────────────────────────────────────────────

class RSACipher:
    """RSA-2048 asymmetric encryption and digital signatures."""

    def __init__(self, key_size: int = 2048):
        print(f"  Generating RSA-{key_size} key pair...")
        t = time.time()
        self._priv = rsa.generate_private_key(65537, key_size, default_backend())
        self._pub  = self._priv.public_key()
        print(f"  Done in {time.time()-t:.3f}s")

    def encrypt(self, plaintext: str) -> Dict:
        ct = self._pub.encrypt(plaintext.encode(), asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return {'algorithm':'RSA-2048-OAEP','ciphertext':base64.b64encode(ct).decode()}

    def decrypt(self, pkg: Dict) -> str:
        return self._priv.decrypt(base64.b64decode(pkg['ciphertext']), asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode()

    def sign(self, message: str) -> Dict:
        sig = self._priv.sign(message.encode(), asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH), hashes.SHA256())
        return {'message':message,'signature':base64.b64encode(sig).decode(),'algorithm':'RSA-PSS-SHA256'}

    def verify(self, signed: Dict) -> bool:
        try:
            self._pub.verify(base64.b64decode(signed['signature']), signed['message'].encode(),
                asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return True
        except: return False


# ── SHA Hashing ──────────────────────────────────────────────

class SHAHasher:
    """SHA-256/512 and HMAC."""
    _MAP = {'SHA-256':hashlib.sha256,'SHA-512':hashlib.sha512,'SHA-384':hashlib.sha384,
            'SHA3-256':hashlib.sha3_256,'SHA3-512':hashlib.sha3_512}

    @staticmethod
    def hash(data: str, alg: str = 'SHA-256') -> str:
        h = SHAHasher._MAP[alg]()
        h.update(data.encode())
        return h.hexdigest()

    @staticmethod
    def hmac_sign(message: str, key: str, alg: str = 'sha256') -> str:
        return hmac.new(key.encode(), message.encode(), alg).hexdigest()

    @staticmethod
    def verify_hmac(message: str, key: str, mac: str, alg: str = 'sha256') -> bool:
        return hmac.compare_digest(SHAHasher.hmac_sign(message, key, alg), mac)

    @staticmethod
    def avalanche(text: str = "Hello, World!") -> None:
        h1 = bin(int(SHAHasher.hash(text), 16))[2:].zfill(256)
        h2 = bin(int(SHAHasher.hash(text+"!"), 16))[2:].zfill(256)
        flipped = sum(a!=b for a,b in zip(h1,h2))
        print(f"\n  Avalanche Effect: '{text}' vs '{text}!'")
        print(f"  Bits flipped: {flipped}/256 = {flipped/256*100:.1f}%  (expect ~50%)")


# ── Password Security ────────────────────────────────────────

class PasswordSecurity:
    """PBKDF2-HMAC-SHA256 secure password hashing with salt."""

    @staticmethod
    def hash_password(pw: str, iters: int = 260_000) -> Dict:
        salt = os.urandom(32)
        t    = time.perf_counter()
        dk   = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iters)
        ms   = (time.perf_counter()-t)*1000
        return {'iterations':iters,'salt':base64.b64encode(salt).decode(),
                'hash':base64.b64encode(dk).decode(),'time_ms':round(ms,2)}

    @staticmethod
    def verify(pw: str, stored: Dict) -> bool:
        dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), base64.b64decode(stored['salt']), stored['iterations'])
        return hmac.compare_digest(base64.b64decode(stored['hash']), dk)


# ── Hybrid Encryption ────────────────────────────────────────

class HybridEncryption:
    """RSA + AES hybrid (mirrors TLS key exchange)."""
    def __init__(self, rsa_cipher: RSACipher): self.rsa = rsa_cipher

    def encrypt(self, message: str) -> Dict:
        aes = AESCipher()
        return {'scheme':'Hybrid RSA-2048 + AES-256-CBC',
                'encrypted_key': self.rsa.encrypt(aes.key_hex),
                'encrypted_msg': aes.encrypt(message)}

    def decrypt(self, pkg: Dict) -> str:
        aes = AESCipher(bytes.fromhex(self.rsa.decrypt(pkg['encrypted_key'])))
        return aes.decrypt(pkg['encrypted_msg'])


# ── Demo ─────────────────────────────────────────────────────

SEP = "─"*65

def main():
    print(f"\n{'═'*65}")
    print("  CRYPTOGRAPHY ALGORITHMS IMPLEMENTATION")
    print("  Cybersecurity Internship — Codec Technologies")
    print(f"{'═'*65}")

    # 1. AES
    print(f"\n{SEP}\n  [1] AES-256-CBC SYMMETRIC ENCRYPTION\n{SEP}")
    pw = "SecureP@ssw0rd!2024"
    aes, salt = AESCipher.from_password(pw)
    msg = "TOP SECRET: Operation Nightfall begins at 0300 hours."
    enc = aes.encrypt(msg)
    dec = aes.decrypt(enc)
    print(f"\n  Password   : {pw}")
    print(f"  Salt       : {salt.hex()}")
    print(f"  Key (AES-256): {aes.key_hex[:40]}...")
    print(f"  Plaintext  : {msg}")
    print(f"  IV         : {enc['iv']}")
    print(f"  Ciphertext : {enc['ciphertext'][:56]}...")
    print(f"  Decrypted  : {dec}")
    print(f"  ✓ Match    : {msg == dec}")

    # 2. SHA
    print(f"\n{SEP}\n  [2] SHA HASH FUNCTIONS\n{SEP}")
    data = "Cryptography secures digital communication."
    print(f"\n  Input: '{data}'\n")
    for alg, fn in SHAHasher._MAP.items():
        digest = SHAHasher.hash(data, alg)
        print(f"  {alg:<12}: {digest[:52]}  ({len(digest)*4}b)")
    SHAHasher.avalanche()

    print(f"\n  HMAC Authentication:")
    key = "my-api-secret-key-2024"
    req = "user=42&action=transfer&amount=5000"
    mac = SHAHasher.hmac_sign(req, key)
    print(f"  Request: {req}")
    print(f"  HMAC   : {mac[:48]}...")
    print(f"  Valid  : ✓ {SHAHasher.verify_hmac(req, key, mac)}")
    print(f"  Tampered: ✗ {SHAHasher.verify_hmac(req+'x', key, mac)}")

    # 3. Passwords
    print(f"\n{SEP}\n  [3] SECURE PASSWORD HASHING (PBKDF2)\n{SEP}")
    for pw in ["password123", "P@ssw0rd!", "horse-battery-staple-99"]:
        stored = PasswordSecurity.hash_password(pw, 100_000)
        print(f"\n  Password  : '{pw}'")
        print(f"  Hash      : {stored['hash'][:40]}...")
        print(f"  Salt      : {stored['salt'][:24]}... (unique!)")
        print(f"  Time      : {stored['time_ms']}ms  (intentionally slow vs ~0ms for MD5)")
        print(f"  Correct   : ✓ {PasswordSecurity.verify(pw, stored)}  |  Wrong : ✗ {PasswordSecurity.verify(pw+'x', stored)}")

    # 4. RSA
    print(f"\n{SEP}\n  [4] RSA-2048 ASYMMETRIC ENCRYPTION & SIGNATURES\n{SEP}")
    rsa_c = RSACipher(2048)
    secret = "AES session key: " + os.urandom(16).hex()
    enc    = rsa_c.encrypt(secret)
    dec    = rsa_c.decrypt(enc)
    print(f"\n  Plaintext  : {secret}")
    print(f"  Ciphertext : {enc['ciphertext'][:56]}...")
    print(f"  Decrypted  : {dec}")
    print(f"  ✓ Match    : {secret == dec}")

    doc    = "I authorize transfer of $10,000 to account 9876-5432."
    signed = rsa_c.sign(doc)
    tampered = {**signed, 'message': doc + " (modified)"}
    print(f"\n  Digital Signature:")
    print(f"  Document   : {doc}")
    print(f"  Signature  : {signed['signature'][:48]}...")
    print(f"  Original   : ✓ {rsa_c.verify(signed)}")
    print(f"  Tampered   : ✗ {rsa_c.verify(tampered)}  ← modification detected!")

    # 5. Hybrid
    print(f"\n{SEP}\n  [5] HYBRID ENCRYPTION (RSA + AES = TLS/HTTPS)\n{SEP}")
    hybrid  = HybridEncryption(rsa_c)
    long_msg = "Confidential: " + "This data is encrypted with AES for speed, but the AES key is protected by RSA. " * 3
    pkg      = hybrid.encrypt(long_msg)
    recovered = hybrid.decrypt(pkg)
    print(f"\n  Scheme    : {pkg['scheme']}")
    print(f"  Message   : {long_msg[:60]}...")
    print(f"  Recovered : {recovered[:60]}...")
    print(f"  ✓ Match   : {long_msg == recovered}")

    print(f"\n{'═'*65}")
    print("  All demos complete! Algorithms: AES-256-CBC | RSA-2048 | SHA | PBKDF2 | Hybrid")
    print(f"{'═'*65}\n")

if __name__ == "__main__":
    main()

"""
crypto_utils.py
===============
Low-level cryptographic building blocks for the password vault.

Design goals
------------
1. Derive the encryption key from the master password with a *memory-hard*
   key-derivation function (Scrypt) so that brute-forcing the master password
   is expensive even with GPUs/ASICs.
2. Encrypt every secret with AES-256 in GCM mode. GCM is an *authenticated*
   cipher: it guarantees both confidentiality (nobody can read the data) and
   integrity (nobody can tamper with the ciphertext without detection).
3. Never reuse a (key, nonce) pair. A fresh random 96-bit nonce is generated
   for every single encryption.

Only the `cryptography` library is used; it is a well-audited, widely used
implementation of these primitives.
"""

from __future__ import annotations

import secrets
import string

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- Key-derivation parameters -------------------------------------------------
# Scrypt cost parameters. Memory used ~= 128 * N * r bytes.
# With N=2**15, r=8  ->  ~32 MB per derivation. That is deliberately slow/heavy
# so an attacker guessing millions of master passwords pays a huge cost, while a
# legitimate single unlock takes only a fraction of a second.
KDF_NAME = "scrypt"
SCRYPT_N = 2 ** 15      # CPU/memory cost factor (must be a power of 2)
SCRYPT_R = 8            # block size
SCRYPT_P = 1            # parallelisation
KEY_LEN = 32           # 32 bytes = AES-256
SALT_LEN = 16          # 128-bit random salt, unique per vault

# AES-GCM nonce length. 96 bits is the recommended size for GCM.
NONCE_LEN = 12


def generate_salt() -> bytes:
    """Return a cryptographically secure random salt for the KDF."""
    return secrets.token_bytes(SALT_LEN)


def derive_key(master_password: str, salt: bytes,
               n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    """
    Turn the master password + salt into a 32-byte AES key using Scrypt.

    The same (password, salt, params) always yields the same key, which is how
    we can decrypt on a later run without ever storing the master password.
    """
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(master_password.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Encrypt `plaintext` with AES-256-GCM.

    Returns  nonce || ciphertext  (the GCM authentication tag is appended to
    the ciphertext automatically by the library). `associated_data` is
    authenticated but NOT encrypted; we use it to bind a ciphertext to its role
    (e.g. "entry" vs "verifier") so blobs cannot be swapped around by an
    attacker who has write access to the database file.
    """
    aes = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_LEN)          # unique per encryption
    ciphertext = aes.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """
    Reverse of `encrypt`. Raises `InvalidTag` (from the cryptography library)
    if the key is wrong or the data was tampered with. Callers rely on this to
    detect an incorrect master password.
    """
    aes = AESGCM(key)
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return aes.decrypt(nonce, ciphertext, associated_data)


# --- Password generator --------------------------------------------------------
def generate_password(length: int = 20,
                      use_lower: bool = True,
                      use_upper: bool = True,
                      use_digits: bool = True,
                      use_symbols: bool = True) -> str:
    """
    Generate a strong random password using the `secrets` module (CSPRNG).

    Guarantees at least one character from every enabled class, then fills the
    rest randomly and shuffles, so the result always satisfies typical
    complexity rules without being predictable.
    """
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")

    if not pools:
        raise ValueError("At least one character class must be enabled.")
    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)}.")

    # one guaranteed character from each enabled class
    chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]

    # secrets-based Fisher-Yates shuffle (random.shuffle is not crypto-safe)
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


# Re-export the exception so other modules don't import the library directly.
WrongKeyOrTamper = InvalidTag

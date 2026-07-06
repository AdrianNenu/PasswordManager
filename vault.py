"""
vault.py
========
The vault ties the crypto layer to persistent storage in SQLite.

Storage model
-------------
The database file holds NOTHING in the clear except the KDF parameters that are
needed to derive the key (the salt and Scrypt cost factors are not secret).
Every credential is stored as an opaque AES-256-GCM blob, so if someone copies
the `.db` file they only see random-looking bytes.

Two tables:

  meta      one row: kdf name, salt, Scrypt params, a "verifier" blob, schema
            version. The verifier is a known constant encrypted with the key;
            being able to decrypt it proves the master password is correct.

  entries   one row per credential: id + the encrypted JSON blob describing the
            entry (title, username, password, url, notes, timestamps).

Because titles are also inside the encrypted blob, the database leaks only the
*number* of stored entries, nothing about their contents.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, asdict
from typing import Optional

import crypto_utils as cu

SCHEMA_VERSION = 1
VERIFIER_PLAINTEXT = b"pwvault-master-check-v1"

# Associated-data tags bind each ciphertext to its purpose (see crypto_utils).
AAD_VERIFIER = b"verifier"
AAD_ENTRY = b"entry"


class VaultError(Exception):
    """Base class for vault problems."""


class WrongMasterPassword(VaultError):
    """Raised when the supplied master password fails verification."""


class VaultLocked(VaultError):
    """Raised when an operation needs an unlocked vault but it is locked."""


@dataclass
class Entry:
    """A single credential. `id` is None until it has been saved."""
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    created: float = 0.0
    modified: float = 0.0
    id: Optional[int] = None


class Vault:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._key: Optional[bytes] = None          # None => locked
        self._salt: Optional[bytes] = None
        self._params = (cu.SCRYPT_N, cu.SCRYPT_R, cu.SCRYPT_P)
        self._ensure_schema()

    # -- schema ---------------------------------------------------------------
    def _ensure_schema(self) -> None:
        c = self._conn
        c.execute(
            """CREATE TABLE IF NOT EXISTS meta (
                   id       INTEGER PRIMARY KEY CHECK (id = 1),
                   kdf      TEXT    NOT NULL,
                   salt     BLOB    NOT NULL,
                   n        INTEGER NOT NULL,
                   r        INTEGER NOT NULL,
                   p        INTEGER NOT NULL,
                   verifier BLOB    NOT NULL,
                   version  INTEGER NOT NULL
               )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS entries (
                   id   INTEGER PRIMARY KEY AUTOINCREMENT,
                   blob BLOB NOT NULL
               )"""
        )
        c.commit()

    def is_initialized(self) -> bool:
        """True if a master password has already been set for this file."""
        row = self._conn.execute("SELECT 1 FROM meta WHERE id = 1").fetchone()
        return row is not None

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    # -- setup / unlock -------------------------------------------------------
    def initialize(self, master_password: str) -> None:
        """Create a brand-new vault protected by `master_password`."""
        if self.is_initialized():
            raise VaultError("Vault is already initialized.")
        salt = cu.generate_salt()
        key = cu.derive_key(master_password, salt, *self._params)
        verifier = cu.encrypt(key, VERIFIER_PLAINTEXT, AAD_VERIFIER)
        self._conn.execute(
            "INSERT INTO meta (id, kdf, salt, n, r, p, verifier, version) "
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
            (cu.KDF_NAME, salt, *self._params, verifier, SCHEMA_VERSION),
        )
        self._conn.commit()
        self._key, self._salt = key, salt

    def unlock(self, master_password: str) -> None:
        """Derive the key and verify it against the stored verifier."""
        row = self._conn.execute(
            "SELECT salt, n, r, p, verifier FROM meta WHERE id = 1"
        ).fetchone()
        if row is None:
            raise VaultError("Vault is not initialized yet.")
        salt = row["salt"]
        params = (row["n"], row["r"], row["p"])
        key = cu.derive_key(master_password, salt, *params)
        try:
            plain = cu.decrypt(key, row["verifier"], AAD_VERIFIER)
        except cu.WrongKeyOrTamper:
            raise WrongMasterPassword("Incorrect master password.")
        if plain != VERIFIER_PLAINTEXT:
            raise WrongMasterPassword("Incorrect master password.")
        self._key, self._salt, self._params = key, salt, params

    def lock(self) -> None:
        """Forget the derived key. Data on disk stays encrypted."""
        self._key = None

    def _require_unlocked(self) -> bytes:
        if self._key is None:
            raise VaultLocked("Vault is locked. Unlock it first.")
        return self._key

    # -- CRUD -----------------------------------------------------------------
    def add_entry(self, entry: Entry) -> int:
        key = self._require_unlocked()
        now = time.time()
        entry.created = now
        entry.modified = now
        blob = self._encrypt_entry(key, entry)
        cur = self._conn.execute("INSERT INTO entries (blob) VALUES (?)", (blob,))
        self._conn.commit()
        entry.id = cur.lastrowid
        return entry.id

    def get_entry(self, entry_id: int) -> Optional[Entry]:
        key = self._require_unlocked()
        row = self._conn.execute(
            "SELECT id, blob FROM entries WHERE id = ?", (entry_id,)
        ).fetchone()
        if row is None:
            return None
        return self._decrypt_entry(key, row["id"], row["blob"])

    def list_entries(self) -> list[Entry]:
        """Return all entries (decrypted), sorted by title."""
        key = self._require_unlocked()
        rows = self._conn.execute("SELECT id, blob FROM entries").fetchall()
        entries = [self._decrypt_entry(key, r["id"], r["blob"]) for r in rows]
        entries.sort(key=lambda e: e.title.lower())
        return entries

    def update_entry(self, entry: Entry) -> None:
        key = self._require_unlocked()
        if entry.id is None:
            raise VaultError("Entry has no id; cannot update.")
        entry.modified = time.time()
        blob = self._encrypt_entry(key, entry)
        self._conn.execute(
            "UPDATE entries SET blob = ? WHERE id = ?", (blob, entry.id)
        )
        self._conn.commit()

    def delete_entry(self, entry_id: int) -> bool:
        self._require_unlocked()
        cur = self._conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def search(self, term: str) -> list[Entry]:
        """Case-insensitive search across title / username / url."""
        term = term.lower()
        return [
            e for e in self.list_entries()
            if term in e.title.lower()
            or term in e.username.lower()
            or term in e.url.lower()
        ]

    # -- change master password ----------------------------------------------
    def change_master_password(self, new_password: str) -> None:
        """
        Re-key the whole vault: new salt, new derived key, re-encrypt the
        verifier and every entry. Done in a single transaction so a crash can
        never leave the vault half-converted.
        """
        old_key = self._require_unlocked()
        new_salt = cu.generate_salt()
        new_key = cu.derive_key(new_password, new_salt, *self._params)

        rows = self._conn.execute("SELECT id, blob FROM entries").fetchall()
        try:
            self._conn.execute("BEGIN")
            for r in rows:
                entry = self._decrypt_entry(old_key, r["id"], r["blob"])
                new_blob = self._encrypt_entry(new_key, entry)
                self._conn.execute(
                    "UPDATE entries SET blob = ? WHERE id = ?", (new_blob, r["id"])
                )
            new_verifier = cu.encrypt(new_key, VERIFIER_PLAINTEXT, AAD_VERIFIER)
            self._conn.execute(
                "UPDATE meta SET salt = ?, verifier = ? WHERE id = 1",
                (new_salt, new_verifier),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        self._key, self._salt = new_key, new_salt

    # -- helpers --------------------------------------------------------------
    def _encrypt_entry(self, key: bytes, entry: Entry) -> bytes:
        payload = asdict(entry)
        payload.pop("id", None)                     # id is a DB concern, not data
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return cu.encrypt(key, raw, AAD_ENTRY)

    def _decrypt_entry(self, key: bytes, entry_id: int, blob: bytes) -> Entry:
        raw = cu.decrypt(key, blob, AAD_ENTRY)
        data = json.loads(raw.decode("utf-8"))
        return Entry(id=entry_id, **data)

    def close(self) -> None:
        self.lock()
        self._conn.close()

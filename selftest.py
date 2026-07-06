import os, sqlite3
import crypto_utils as cu
from vault import Vault, Entry, WrongMasterPassword, VaultLocked

DB = "test.db"
if os.path.exists(DB): os.remove(DB)

# 1) init + unlock
v = Vault(DB)
assert not v.is_initialized()
v.initialize("CorrectHorse1!")
assert v.is_unlocked
print("1. init/unlock OK")

# 2) add + retrieve
eid = v.add_entry(Entry(title="GitHub", username="andrei", password="p@ss123", url="github.com", notes="work"))
got = v.get_entry(eid)
assert got.title == "GitHub" and got.password == "p@ss123"
print("2. add/get OK, id =", eid)

# 3) add more + list sorting
v.add_entry(Entry(title="Amazon", username="a@b.com", password="zzz"))
v.add_entry(Entry(title="bank", username="client99", password="secret"))
titles = [e.title for e in v.list_entries()]
assert titles == sorted(titles, key=str.lower), titles
print("3. list sorted OK:", titles)

# 4) search
res = v.search("git")
assert len(res) == 1 and res[0].title == "GitHub"
print("4. search OK")

# 5) update
got.password = "new-p@ss"
v.update_entry(got)
assert v.get_entry(eid).password == "new-p@ss"
print("5. update OK")

# 6) delete
assert v.delete_entry(eid) is True
assert v.get_entry(eid) is None
print("6. delete OK")

# 7) lock blocks access
v.lock()
try:
    v.list_entries(); assert False
except VaultLocked:
    print("7. lock blocks access OK")

# 8) wrong master rejected, correct accepted
try:
    v.unlock("WrongPassword"); assert False
except WrongMasterPassword:
    pass
v.unlock("CorrectHorse1!")
print("8. wrong/correct master OK")

# 9) database contains only ciphertext (no plaintext leakage)
v.close()
raw = open(DB, "rb").read()
for secret in [b"Amazon", b"client99", b"secret", b"a@b.com"]:
    assert secret not in raw, f"LEAK: {secret!r} found in db file!"
print("9. no plaintext in db file OK")

# 10) change master password, then unlock with new only
v = Vault(DB); v.unlock("CorrectHorse1!")
before = {e.title: e.password for e in v.list_entries()}
v.change_master_password("BrandNewMaster2@")
v.close()
v = Vault(DB)
try:
    v.unlock("CorrectHorse1!"); assert False
except WrongMasterPassword:
    pass
v.unlock("BrandNewMaster2@")
after = {e.title: e.password for e in v.list_entries()}
assert before == after, (before, after)
print("10. change master + re-encrypt OK")

# 11) tamper detection (flip a byte in an entry blob)
v.close()
conn = sqlite3.connect(DB)
row = conn.execute("SELECT id, blob FROM entries LIMIT 1").fetchone()
bad = bytearray(row[1]); bad[-1] ^= 0x01
conn.execute("UPDATE entries SET blob=? WHERE id=?", (bytes(bad), row[0])); conn.commit(); conn.close()
v = Vault(DB); v.unlock("BrandNewMaster2@")
try:
    v.list_entries(); assert False, "tamper not detected!"
except cu.WrongKeyOrTamper:
    print("11. tamper detection (GCM auth) OK")
v.close()

# 12) password generator sanity
p = cu.generate_password(24)
assert len(p) == 24
assert any(c.islower() for c in p) and any(c.isupper() for c in p)
assert any(c.isdigit() for c in p) and any(not c.isalnum() for c in p)
print("12. generator OK:", p)

print("\nALL TESTS PASSED")

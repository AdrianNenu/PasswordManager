from __future__ import annotations

import getpass
import sys
from datetime import datetime

import crypto_utils as cu
from vault import Entry, Vault, WrongMasterPassword

DEFAULT_DB = "vault.db"
MAX_UNLOCK_TRIES = 3


# --- small input helpers -------------------------------------------------------
def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def ask_secret(prompt: str) -> str:
    """Read a value without echoing it to the screen."""
    return getpass.getpass(f"{prompt}: ")


def confirm(prompt: str) -> bool:
    return ask(f"{prompt} (y/n)", "n").lower().startswith("y")


def fmt_time(ts: float) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# --- unlock / setup flow -------------------------------------------------------
def setup_new_vault(vault: Vault) -> bool:
    print("No vault found. Let's create one.")
    while True:
        pw1 = ask_secret("Choose a master password")
        if len(pw1) < 8:
            print("  Please use at least 8 characters.\n")
            continue
        pw2 = ask_secret("Confirm master password")
        if pw1 != pw2:
            print("  Passwords do not match. Try again.\n")
            continue
        break
    vault.initialize(pw1)
    print("Vault created and unlocked.\n")
    return True


def unlock_vault(vault: Vault) -> bool:
    for attempt in range(1, MAX_UNLOCK_TRIES + 1):
        pw = ask_secret("Master password")
        try:
            vault.unlock(pw)
            print("Vault unlocked.\n")
            return True
        except WrongMasterPassword:
            left = MAX_UNLOCK_TRIES - attempt
            print(f"  Wrong password. {left} attempt(s) left.\n")
    print("Too many failed attempts. Exiting.")
    return False


# --- menu actions --------------------------------------------------------------
def action_add(vault: Vault) -> None:
    print("\n-- New entry --")
    title = ask("Title/site (required)")
    if not title:
        print("Title is required. Cancelled.\n")
        return
    username = ask("Username/email")

    if confirm("Generate a strong password automatically?"):
        length_str = ask("Length", "20")
        try:
            length = int(length_str)
        except ValueError:
            length = 20
        password = cu.generate_password(length=length)
        print(f"  Generated: {password}")
    else:
        password = ask_secret("Password")

    url = ask("URL")
    notes = ask("Notes")

    entry = Entry(title=title, username=username, password=password,
                  url=url, notes=notes)
    new_id = vault.add_entry(entry)
    print(f"Saved as entry #{new_id}.\n")


def action_list(vault: Vault) -> None:
    entries = vault.list_entries()
    if not entries:
        print("\n(No entries yet.)\n")
        return
    print("\n  ID   Title                          Username")
    print("  " + "-" * 55)
    for e in entries:
        print(f"  {e.id:<4} {e.title[:30]:<30} {e.username[:20]}")
    print()


def _pick_entry(vault: Vault) -> Entry | None:
    id_str = ask("Entry ID")
    if not id_str.isdigit():
        print("Please enter a numeric ID.\n")
        return None
    entry = vault.get_entry(int(id_str))
    if entry is None:
        print("No entry with that ID.\n")
    return entry


def action_view(vault: Vault) -> None:
    entry = _pick_entry(vault)
    if entry is None:
        return
    print("\n-- Entry details --")
    print(f"  ID       : {entry.id}")
    print(f"  Title    : {entry.title}")
    print(f"  Username : {entry.username}")
    print(f"  Password : {entry.password}")
    print(f"  URL      : {entry.url}")
    print(f"  Notes    : {entry.notes}")
    print(f"  Created  : {fmt_time(entry.created)}")
    print(f"  Modified : {fmt_time(entry.modified)}\n")


def action_search(vault: Vault) -> None:
    term = ask("Search term")
    results = vault.search(term)
    if not results:
        print("No matches.\n")
        return
    print(f"\n  {len(results)} match(es):")
    for e in results:
        print(f"  #{e.id}  {e.title}  ({e.username})")
    print()


def action_edit(vault: Vault) -> None:
    entry = _pick_entry(vault)
    if entry is None:
        return
    print("Leave a field blank to keep the current value.")
    entry.title = ask("Title", entry.title)
    entry.username = ask("Username", entry.username)
    if confirm("Change password?"):
        if confirm("Generate a new one?"):
            entry.password = cu.generate_password()
            print(f"  Generated: {entry.password}")
        else:
            entry.password = ask_secret("New password")
    entry.url = ask("URL", entry.url)
    entry.notes = ask("Notes", entry.notes)
    vault.update_entry(entry)
    print("Updated.\n")


def action_delete(vault: Vault) -> None:
    entry = _pick_entry(vault)
    if entry is None:
        return
    if confirm(f"Really delete '{entry.title}'?"):
        vault.delete_entry(entry.id)
        print("Deleted.\n")
    else:
        print("Cancelled.\n")


def action_generate(vault: Vault) -> None:
    length_str = ask("Length", "20")
    try:
        length = int(length_str)
    except ValueError:
        length = 20
    print(f"  {cu.generate_password(length=length)}\n")


def action_change_master(vault: Vault) -> None:
    print("\n-- Change master password --")
    current = ask_secret("Current master password")
    try:
        vault.unlock(current)          # re-verify before allowing change
    except WrongMasterPassword:
        print("Current password incorrect.\n")
        return
    new1 = ask_secret("New master password")
    if len(new1) < 8:
        print("Please use at least 8 characters.\n")
        return
    new2 = ask_secret("Confirm new master password")
    if new1 != new2:
        print("Passwords do not match.\n")
        return
    vault.change_master_password(new1)
    print("Master password changed and vault re-encrypted.\n")


MENU = """\
==================== Password Vault ====================
  1) List entries        5) Edit entry
  2) View entry          6) Delete entry
  3) Add entry           7) Generate password
  4) Search              8) Change master password
  9) Lock & quit
========================================================"""


def main() -> None:
    db_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB
    vault = Vault(db_path)
    print(f"Opening vault: {db_path}")

    ok = setup_new_vault(vault) if not vault.is_initialized() else unlock_vault(vault)
    if not ok:
        vault.close()
        return

    actions = {
        "1": action_list, "2": action_view, "3": action_add,
        "4": action_search, "5": action_edit, "6": action_delete,
        "7": action_generate, "8": action_change_master,
    }

    try:
        while True:
            print(MENU)
            choice = ask("Choose an option")
            if choice == "9":
                break
            handler = actions.get(choice)
            if handler is None:
                print("Unknown option.\n")
                continue
            try:
                handler(vault)
            except Exception as exc:                 # keep the app alive on errors
                print(f"Error: {exc}\n")
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        vault.close()
        print("Vault locked. Bye.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
pwmanager_gui.py
================
A polished graphical interface (Tkinter/ttk) for the encrypted password vault.

It reuses the exact same backend as the command-line version:
  * crypto_utils.py  -> Scrypt KDF, AES-256-GCM, password generator
  * vault.py         -> encrypted SQLite storage + CRUD

Run it with:
    python3 pwmanager_gui.py            # uses ./vault.db
    python3 pwmanager_gui.py mine.db    # custom vault file

Features
--------
* Create-vault / unlock screens (master password hidden).
* Entry list with live search.
* Details panel with a **Show/Hide** toggle to reveal a stored password,
  plus one-click copy (clipboard auto-clears after 20 s).
* Add / Edit / Delete dialogs with a built-in strong-password generator.
* Change master password (re-encrypts the whole vault).
* Auto-lock after 5 minutes of inactivity, and a manual Lock button.
"""

from __future__ import annotations

import sys
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox

import crypto_utils as cu
from vault import Entry, Vault, WrongMasterPassword

DEFAULT_DB = "vault.db"
AUTOLOCK_MS = 5 * 60 * 1000          # auto-lock after 5 minutes idle
CLIPBOARD_CLEAR_MS = 20 * 1000       # clear copied password after 20 seconds

# --- colour palette -----------------------------------------------------------
BG = "#f3f5f9"          # window background
CARD = "#ffffff"        # panels
ACCENT = "#2b4c7e"      # primary blue (matches the project theme)
ACCENT_DK = "#213d66"
DANGER = "#b3261e"
TEXT = "#1f2933"
MUTED = "#66788a"
BORDER = "#d9e0e8"


class PasswordManagerGUI:
    def __init__(self, root: tk.Tk, db_path: str):
        self.root = root
        self.vault = Vault(db_path)
        self.db_path = db_path
        self.selected: Entry | None = None
        self._password_visible = False
        self._autolock_id: str | None = None

        root.title("Password Vault")
        root.geometry("880x560")
        root.minsize(760, 480)
        root.configure(bg=BG)

        self._init_styles()

        # container that holds whichever screen is active
        self.container = ttk.Frame(root, style="App.TFrame")
        self.container.pack(fill="both", expand=True)

        # global activity binding for the idle auto-lock timer
        root.bind_all("<Any-KeyPress>", self._reset_autolock)
        root.bind_all("<Any-Button>", self._reset_autolock)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._show_unlock_screen()

    # ------------------------------------------------------------------ styles
    def _init_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("App.TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=CARD, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=CARD, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=ACCENT,
                        font=("Segoe UI Semibold", 22))
        style.configure("H2.TLabel", background=CARD, foreground=TEXT,
                        font=("Segoe UI Semibold", 13))
        style.configure("Field.TLabel", background=CARD, foreground=MUTED,
                        font=("Segoe UI", 9))
        style.configure("Value.TLabel", background=CARD, foreground=TEXT,
                        font=("Segoe UI", 11))

        style.configure("TEntry", fieldbackground="#ffffff", padding=6)

        # buttons
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                        font=("Segoe UI Semibold", 10), padding=(14, 8), borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", ACCENT_DK), ("pressed", ACCENT_DK)])
        style.configure("Ghost.TButton", background=CARD, foreground=ACCENT,
                        font=("Segoe UI", 10), padding=(10, 6), borderwidth=1)
        style.map("Ghost.TButton", background=[("active", "#eef2f8")])
        style.configure("Danger.TButton", background=DANGER, foreground="#ffffff",
                        font=("Segoe UI Semibold", 10), padding=(10, 6), borderwidth=0)
        style.map("Danger.TButton", background=[("active", "#8f1e17")])
        style.configure("Small.TButton", padding=(8, 4), font=("Segoe UI", 9))

        # treeview
        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff",
                        foreground=TEXT, rowheight=28, font=("Segoe UI", 10),
                        borderwidth=0)
        style.configure("Treeview.Heading", background="#e9eef5", foreground=ACCENT_DK,
                        font=("Segoe UI Semibold", 10), padding=6)
        style.map("Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", "#ffffff")])

    def _clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()

    # ------------------------------------------------------------- unlock screen
    def _show_unlock_screen(self):
        self._cancel_autolock()
        self._clear_container()
        self.selected = None

        wrap = ttk.Frame(self.container, style="App.TFrame")
        wrap.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(wrap, text="🔒  Password Vault", style="Title.TLabel").pack(pady=(0, 6))
        first_time = not self.vault.is_initialized()
        subtitle = "Create a master password to protect your vault." if first_time \
            else "Enter your master password to unlock."
        ttk.Label(wrap, text=subtitle, foreground=MUTED,
                  background=BG, font=("Segoe UI", 10)).pack(pady=(0, 18))

        card = tk.Frame(wrap, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(ipadx=26, ipady=22)

        ttk.Label(card, text="Master password", style="Field.TLabel").grid(
            row=0, column=0, sticky="w", padx=20, pady=(4, 2))
        pw1 = ttk.Entry(card, show="•", width=34)
        pw1.grid(row=1, column=0, padx=20)
        pw1.focus_set()

        pw2 = None
        if first_time:
            ttk.Label(card, text="Confirm master password", style="Field.TLabel").grid(
                row=2, column=0, sticky="w", padx=20, pady=(12, 2))
            pw2 = ttk.Entry(card, show="•", width=34)
            pw2.grid(row=3, column=0, padx=20)

        err = ttk.Label(card, text="", foreground=DANGER, background=CARD,
                        font=("Segoe UI", 9))
        err.grid(row=4, column=0, pady=(10, 0))

        def submit(event=None):
            p1 = pw1.get()
            if first_time:
                if len(p1) < 8:
                    err.config(text="Please use at least 8 characters."); return
                if p1 != pw2.get():
                    err.config(text="Passwords do not match."); return
                self.vault.initialize(p1)
                self._show_main_screen()
            else:
                try:
                    self.vault.unlock(p1)
                    self._show_main_screen()
                except WrongMasterPassword:
                    err.config(text="Incorrect master password.")
                    pw1.delete(0, "end")

        btn_text = "Create Vault" if first_time else "Unlock"
        ttk.Button(card, text=btn_text, style="Accent.TButton",
                   command=submit).grid(row=5, column=0, sticky="ew", padx=20, pady=(16, 4))

        pw1.bind("<Return>", submit)
        if pw2 is not None:
            pw2.bind("<Return>", submit)

        ttk.Label(wrap, text=f"Vault file: {self.db_path}", background=BG,
                  foreground=MUTED, font=("Segoe UI", 8)).pack(pady=(16, 0))

    # --------------------------------------------------------------- main screen
    def _show_main_screen(self):
        self._clear_container()
        self._reset_autolock()

        # ---- top toolbar ----
        toolbar = ttk.Frame(self.container, style="App.TFrame")
        toolbar.pack(fill="x", padx=16, pady=(14, 8))

        ttk.Label(toolbar, text="Password Vault", style="Title.TLabel").pack(side="left")

        ttk.Button(toolbar, text="Lock", style="Ghost.TButton",
                   command=self._lock).pack(side="right")
        ttk.Button(toolbar, text="Change master", style="Ghost.TButton",
                   command=self._change_master_dialog).pack(side="right", padx=(0, 8))
        ttk.Button(toolbar, text="Generator", style="Ghost.TButton",
                   command=self._generator_dialog).pack(side="right", padx=(0, 8))
        ttk.Button(toolbar, text="+  Add entry", style="Accent.TButton",
                   command=self._add_entry_dialog).pack(side="right", padx=(0, 8))

        # ---- search bar ----
        search_row = ttk.Frame(self.container, style="App.TFrame")
        search_row.pack(fill="x", padx=16, pady=(0, 8))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_list())
        se = ttk.Entry(search_row, textvariable=self.search_var)
        se.pack(fill="x")
        se.insert(0, "")
        self._add_placeholder(se, "Search by title, username or URL…")

        # ---- body: list (left) + details (right) ----
        body = ttk.Frame(self.container, style="App.TFrame")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=4)
        body.rowconfigure(0, weight=1)

        # list
        list_card = tk.Frame(body, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        list_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.tree = ttk.Treeview(list_card, columns=("title", "user"),
                                 show="headings", selectmode="browse")
        self.tree.heading("title", text="Title")
        self.tree.heading("user", text="Username")
        self.tree.column("title", width=170, anchor="w")
        self.tree.column("user", width=170, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        vs = ttk.Scrollbar(list_card, orient="vertical", command=self.tree.yview)
        vs.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.tag_configure("odd", background="#f7f9fc")

        # details
        self.details = tk.Frame(body, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        self.details.grid(row=0, column=1, sticky="nsew")
        self._build_details_panel()

        # ---- status bar ----
        self.status = tk.StringVar(value="Vault unlocked.")
        bar = tk.Frame(self.container, bg="#e9eef5")
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.status, bg="#e9eef5", fg=MUTED,
                 anchor="w", font=("Segoe UI", 9), padx=14, pady=5).pack(fill="x")

        self._refresh_list()

    # ---- details panel ----
    def _build_details_panel(self):
        for w in self.details.winfo_children():
            w.destroy()

        self._empty_label = ttk.Label(
            self.details, text="Select an entry to see its details.",
            style="Muted.TLabel")
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

        self._detail_body = tk.Frame(self.details, bg=CARD)
        # populated in _on_select; hidden until then

        pad = {"padx": 22}
        self.v_title = tk.StringVar()
        ttk.Label(self._detail_body, textvariable=self.v_title, style="H2.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(20, 14), **pad)

        def field(row, caption):
            ttk.Label(self._detail_body, text=caption, style="Field.TLabel").grid(
                row=row, column=0, columnspan=2, sticky="w", pady=(8, 0), **pad)

        # username
        field(1, "USERNAME")
        self.v_user = tk.StringVar()
        ttk.Label(self._detail_body, textvariable=self.v_user, style="Value.TLabel").grid(
            row=2, column=0, sticky="w", **pad)
        ttk.Button(self._detail_body, text="Copy", style="Small.TButton",
                   command=lambda: self._copy(self.v_user.get(), "Username")).grid(
            row=2, column=1, sticky="e", padx=(0, 22))

        # password (masked + show/hide + copy)
        field(3, "PASSWORD")
        self.pw_entry = ttk.Entry(self._detail_body, show="•", width=30)
        self.pw_entry.grid(row=4, column=0, sticky="w", padx=(22, 0))
        self.pw_entry.configure(state="readonly")
        btns = tk.Frame(self._detail_body, bg=CARD)
        btns.grid(row=4, column=1, sticky="e", padx=(0, 22))
        self.show_btn = ttk.Button(btns, text="Show", style="Small.TButton",
                                   command=self._toggle_password)
        self.show_btn.pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Copy", style="Small.TButton",
                   command=lambda: self._copy(self.selected.password if self.selected else "",
                                              "Password")).pack(side="left")

        # url
        field(5, "URL")
        self.v_url = tk.StringVar()
        ttk.Label(self._detail_body, textvariable=self.v_url, style="Value.TLabel").grid(
            row=6, column=0, columnspan=2, sticky="w", **pad)

        # notes
        field(7, "NOTES")
        self.notes_box = tk.Text(self._detail_body, height=4, width=40, wrap="word",
                                 bg="#f7f9fc", fg=TEXT, relief="flat",
                                 font=("Segoe UI", 10), padx=8, pady=6)
        self.notes_box.grid(row=8, column=0, columnspan=2, sticky="ew", padx=22, pady=(2, 6))
        self.notes_box.configure(state="disabled")

        self.v_meta = tk.StringVar()
        ttk.Label(self._detail_body, textvariable=self.v_meta, style="Muted.TLabel").grid(
            row=9, column=0, columnspan=2, sticky="w", **pad)

        actions = tk.Frame(self._detail_body, bg=CARD)
        actions.grid(row=10, column=0, columnspan=2, sticky="e", padx=22, pady=(16, 18))
        ttk.Button(actions, text="Edit", style="Ghost.TButton",
                   command=self._edit_entry_dialog).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Delete", style="Danger.TButton",
                   command=self._delete_selected).pack(side="left")

        self._detail_body.columnconfigure(0, weight=1)

    # ---- list / selection ----
    def _refresh_list(self):
        if not hasattr(self, "tree"):
            return
        term = getattr(self, "search_var", tk.StringVar()).get().strip()
        if term and term != "Search by title, username or URL…":
            entries = self.vault.search(term)
        else:
            entries = self.vault.list_entries()

        self.tree.delete(*self.tree.get_children())
        for i, e in enumerate(entries):
            tag = "odd" if i % 2 else "even"
            self.tree.insert("", "end", iid=str(e.id),
                             values=(e.title, e.username), tags=(tag,))
        self._clear_details()
        self.status.set(f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}.")

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        entry = self.vault.get_entry(int(sel[0]))
        if entry is None:
            return
        self.selected = entry
        self._password_visible = False

        self._empty_label.place_forget()
        self._detail_body.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.v_title.set(entry.title)
        self.v_user.set(entry.username or "—")
        self.v_url.set(entry.url or "—")
        self.pw_entry.configure(state="normal")
        self.pw_entry.delete(0, "end")
        self.pw_entry.insert(0, entry.password)
        self.pw_entry.configure(show="•", state="readonly")
        self.show_btn.configure(text="Show")

        self.notes_box.configure(state="normal")
        self.notes_box.delete("1.0", "end")
        self.notes_box.insert("1.0", entry.notes or "—")
        self.notes_box.configure(state="disabled")

        self.v_meta.set(f"Created {self._fmt(entry.created)}   ·   "
                        f"Modified {self._fmt(entry.modified)}")

    def _clear_details(self):
        self.selected = None
        if hasattr(self, "_detail_body"):
            self._detail_body.place_forget()
            self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

    def _toggle_password(self):
        if not self.selected:
            return
        self._password_visible = not self._password_visible
        self.pw_entry.configure(show="" if self._password_visible else "•")
        self.show_btn.configure(text="Hide" if self._password_visible else "Show")

    # ---- add / edit dialog ----
    def _entry_dialog(self, title, entry: Entry | None):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=CARD)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        pad = {"padx": 20, "pady": 4}
        row = 0

        def labeled(caption):
            nonlocal row
            ttk.Label(dlg, text=caption, style="Field.TLabel").grid(
                row=row, column=0, columnspan=2, sticky="w", **pad)
            row += 1
            e = ttk.Entry(dlg, width=40)
            e.grid(row=row, column=0, columnspan=2, sticky="ew", padx=20)
            row += 1
            return e

        ttk.Label(dlg, text=title, style="H2.TLabel").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=20, pady=(18, 8))
        row += 1

        e_title = labeled("Title / site *")
        e_user = labeled("Username / email")

        ttk.Label(dlg, text="Password", style="Field.TLabel").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad); row += 1
        pw_frame = tk.Frame(dlg, bg=CARD)
        pw_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=20); row += 1
        e_pass = ttk.Entry(pw_frame, show="•")
        e_pass.pack(side="left", fill="x", expand=True)
        show_state = {"on": False}

        def toggle():
            show_state["on"] = not show_state["on"]
            e_pass.configure(show="" if show_state["on"] else "•")
            tgl.configure(text="Hide" if show_state["on"] else "Show")

        tgl = ttk.Button(pw_frame, text="Show", style="Small.TButton", command=toggle)
        tgl.pack(side="left", padx=(6, 0))

        def gen():
            e_pass.delete(0, "end")
            e_pass.insert(0, cu.generate_password(20))
            if not show_state["on"]:
                toggle()
        ttk.Button(pw_frame, text="Generate", style="Small.TButton",
                   command=gen).pack(side="left", padx=(6, 0))

        e_url = labeled("URL")

        ttk.Label(dlg, text="Notes", style="Field.TLabel").grid(
            row=row, column=0, columnspan=2, sticky="w", **pad); row += 1
        notes = tk.Text(dlg, height=3, width=40, wrap="word", relief="solid",
                        borderwidth=1, font=("Segoe UI", 10), padx=6, pady=4)
        notes.grid(row=row, column=0, columnspan=2, sticky="ew", padx=20); row += 1

        if entry is not None:
            e_title.insert(0, entry.title)
            e_user.insert(0, entry.username)
            e_pass.insert(0, entry.password)
            e_url.insert(0, entry.url)
            notes.insert("1.0", entry.notes)

        err = ttk.Label(dlg, text="", foreground=DANGER, background=CARD,
                        font=("Segoe UI", 9))
        err.grid(row=row, column=0, columnspan=2, padx=20, pady=(6, 0)); row += 1

        def save():
            t = e_title.get().strip()
            if not t:
                err.config(text="Title is required."); return
            data = dict(title=t, username=e_user.get().strip(),
                        password=e_pass.get(), url=e_url.get().strip(),
                        notes=notes.get("1.0", "end").strip())
            if entry is None:
                self.vault.add_entry(Entry(**data))
                self.status.set(f"Added '{t}'.")
            else:
                for k, v in data.items():
                    setattr(entry, k, v)
                self.vault.update_entry(entry)
                self.status.set(f"Updated '{t}'.")
            dlg.destroy()
            self._refresh_list()

        btns = tk.Frame(dlg, bg=CARD)
        btns.grid(row=row, column=0, columnspan=2, sticky="e", padx=20, pady=(10, 18))
        ttk.Button(btns, text="Cancel", style="Ghost.TButton",
                   command=dlg.destroy).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Save", style="Accent.TButton",
                   command=save).pack(side="left")

        dlg.columnconfigure(0, weight=1)
        e_title.focus_set()
        self._center(dlg)

    def _add_entry_dialog(self):
        self._entry_dialog("Add entry", None)

    def _edit_entry_dialog(self):
        if self.selected:
            self._entry_dialog("Edit entry", self.selected)

    def _delete_selected(self):
        if not self.selected:
            return
        if messagebox.askyesno("Delete entry",
                               f"Delete '{self.selected.title}'? This cannot be undone."):
            self.vault.delete_entry(self.selected.id)
            self.status.set("Entry deleted.")
            self._refresh_list()

    # ---- generator dialog ----
    def _generator_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Password generator")
        dlg.configure(bg=CARD)
        dlg.transient(self.root); dlg.grab_set(); dlg.resizable(False, False)

        ttk.Label(dlg, text="Password generator", style="H2.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(18, 10))

        ttk.Label(dlg, text="Length", style="Field.TLabel").grid(
            row=1, column=0, sticky="w", padx=20)
        length = tk.IntVar(value=20)
        ttk.Spinbox(dlg, from_=6, to=64, textvariable=length, width=6).grid(
            row=1, column=1, sticky="w", padx=20)

        lower = tk.BooleanVar(value=True); upper = tk.BooleanVar(value=True)
        digits = tk.BooleanVar(value=True); symbols = tk.BooleanVar(value=True)
        opts = tk.Frame(dlg, bg=CARD)
        opts.grid(row=2, column=0, columnspan=2, sticky="w", padx=16, pady=8)
        for text, var in [("a-z", lower), ("A-Z", upper),
                          ("0-9", digits), ("!@#", symbols)]:
            tk.Checkbutton(opts, text=text, variable=var, bg=CARD,
                           font=("Segoe UI", 10)).pack(side="left", padx=6)

        result = tk.StringVar()
        out = ttk.Entry(dlg, textvariable=result, width=36, font=("Consolas", 11))
        out.grid(row=3, column=0, columnspan=2, sticky="ew", padx=20, pady=(4, 4))

        def do_generate():
            try:
                result.set(cu.generate_password(
                    length.get(), lower.get(), upper.get(),
                    digits.get(), symbols.get()))
            except ValueError as ex:
                result.set(f"⚠ {ex}")

        do_generate()
        btns = tk.Frame(dlg, bg=CARD)
        btns.grid(row=4, column=0, columnspan=2, sticky="e", padx=20, pady=(6, 18))
        ttk.Button(btns, text="Regenerate", style="Ghost.TButton",
                   command=do_generate).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Copy", style="Accent.TButton",
                   command=lambda: self._copy(result.get(), "Password")).pack(side="left")

        dlg.columnconfigure(0, weight=1)
        self._center(dlg)

    # ---- change master password ----
    def _change_master_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Change master password")
        dlg.configure(bg=CARD)
        dlg.transient(self.root); dlg.grab_set(); dlg.resizable(False, False)

        ttk.Label(dlg, text="Change master password", style="H2.TLabel").grid(
            row=0, column=0, sticky="w", padx=20, pady=(18, 10))

        def pwrow(r, caption):
            ttk.Label(dlg, text=caption, style="Field.TLabel").grid(
                row=r, column=0, sticky="w", padx=20, pady=(6, 0))
            e = ttk.Entry(dlg, show="•", width=34)
            e.grid(row=r + 1, column=0, padx=20)
            return e

        cur = pwrow(1, "Current master password")
        new1 = pwrow(3, "New master password")
        new2 = pwrow(5, "Confirm new master password")
        err = ttk.Label(dlg, text="", foreground=DANGER, background=CARD,
                        font=("Segoe UI", 9))
        err.grid(row=7, column=0, padx=20, pady=(8, 0))

        def apply():
            try:
                self.vault.unlock(cur.get())
            except WrongMasterPassword:
                err.config(text="Current password is incorrect."); return
            if len(new1.get()) < 8:
                err.config(text="New password must be at least 8 characters."); return
            if new1.get() != new2.get():
                err.config(text="New passwords do not match."); return
            self.vault.change_master_password(new1.get())
            dlg.destroy()
            self.status.set("Master password changed. Vault re-encrypted.")
            messagebox.showinfo("Done", "Master password changed successfully.")

        btns = tk.Frame(dlg, bg=CARD)
        btns.grid(row=8, column=0, sticky="e", padx=20, pady=(12, 18))
        ttk.Button(btns, text="Cancel", style="Ghost.TButton",
                   command=dlg.destroy).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Change", style="Accent.TButton",
                   command=apply).pack(side="left")
        cur.focus_set()
        self._center(dlg)

    # ---- clipboard, lock, helpers ----
    def _copy(self, text, label="Value"):
        if not text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.set(f"{label} copied — clipboard clears in 20s.")
        self.root.after(CLIPBOARD_CLEAR_MS, lambda: self._clear_clipboard_if(text))

    def _clear_clipboard_if(self, text):
        try:
            if self.root.clipboard_get() == text:
                self.root.clipboard_clear()
                self.status.set("Clipboard cleared.")
        except tk.TclError:
            pass

    def _lock(self):
        self.vault.lock()
        self._show_unlock_screen()

    # auto-lock timer
    def _reset_autolock(self, event=None):
        self._cancel_autolock()
        if self.vault.is_unlocked:
            self._autolock_id = self.root.after(AUTOLOCK_MS, self._autolock)

    def _cancel_autolock(self):
        if self._autolock_id is not None:
            try:
                self.root.after_cancel(self._autolock_id)
            except tk.TclError:
                pass
            self._autolock_id = None

    def _autolock(self):
        if self.vault.is_unlocked:
            self.vault.lock()
            self._show_unlock_screen()
            messagebox.showinfo("Locked", "Vault auto-locked after inactivity.")

    def _on_close(self):
        try:
            self.vault.close()
        finally:
            self.root.destroy()

    # small utilities
    @staticmethod
    def _fmt(ts):
        if not ts:
            return "—"
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

    def _center(self, win):
        win.update_idletasks()
        w, h = win.winfo_width(), win.winfo_height()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - h) // 3
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _add_placeholder(self, entry, text):
        entry.insert(0, text)
        entry.configure(foreground=MUTED)

        def on_focus_in(_):
            if entry.get() == text:
                entry.delete(0, "end")
                entry.configure(foreground=TEXT)

        def on_focus_out(_):
            if not entry.get():
                entry.insert(0, text)
                entry.configure(foreground=MUTED)

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB
    root = tk.Tk()
    PasswordManagerGUI(root, db_path)
    root.mainloop()


if __name__ == "__main__":
    main()

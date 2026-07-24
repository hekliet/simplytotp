#!/usr/bin/env python
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import tkinter.simpledialog as simpledialog
import tkinter.ttk as ttk
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from cryptography.fernet import InvalidToken

from PIL import Image
from pyzbar.pyzbar import decode as qr_decode

from simplytotp import (
    TOTPRecord,
    export_json,
    import_json,
    load_records,
    search_records,
    create_totp,
    remaining_secs,
    store_records,
)


class TOTPApp:
    def __init__(self, root: tk.Tk, records: list[TOTPRecord],
                 password: str) -> None:
        self.root = root
        self.password = password
        self.records = records
        root.title("SimpleTOTP")
        root.minsize(600, 300)

        menubar = tk.Menu(root)
        root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="File", menu=file_menu, underline=0)
        file_menu.add_command(label="Import from file\u2026",
                              command=self.on_import, underline=0)
        file_menu.add_command(label="Export to file\u2026",
                              command=self.on_export, underline=0)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.on_quit, underline=0)

        root.protocol("WM_DELETE_WINDOW", self.on_quit)

        toolbar = tk.Frame(root)
        toolbar.pack(fill=tk.X, padx=4, pady=(4, 0))

        self.add_btn = tk.Button(
            toolbar, text="Add", underline=0,
            command=self.on_add, width=8)
        self.add_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.del_btn = tk.Button(
            toolbar, text="Delete", underline=0,
            command=self.on_delete, width=8)
        self.del_btn.pack(side=tk.LEFT)

        root.bind("<Alt-a>", lambda e: self.on_add())
        root.bind("<Alt-A>", lambda e: self.on_add())
        root.bind("<Alt-d>", lambda e: self.on_delete())
        root.bind("<Alt-D>", lambda e: self.on_delete())

        self.items: list[tuple[TOTPRecord, "pyotp.TOTP"]] = [
            (r, create_totp(r)) for r in records
        ]
        self.filtered: list[tuple[TOTPRecord, "pyotp.TOTP"]] = list(self.items)

        filter_frame = ttk.Frame(root, padding=4)
        filter_frame.pack(fill=tk.X)
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self.on_filter_changed)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        filter_entry.focus()
        filter_entry.bind("<Control-a>", self.select_all)
        filter_entry.bind("<Control-A>", self.select_all)

        list_frame = ttk.Frame(root)
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("name", "issuer", "code", "remaining")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings",
                                 selectmode="extended")

        self.tree.heading("name", text="Name")
        self.tree.heading("issuer", text="Issuer")
        self.tree.heading("code", text="Code")
        self.tree.heading("remaining", text="Remaining")

        self.tree.column("name", width=200)
        self.tree.column("issuer", width=120)
        self.tree.column("code", width=120, anchor=tk.CENTER)
        self.tree.column("remaining", width=80, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<ButtonRelease-1>", self.on_item_click)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var,
                               relief=tk.SUNKEN, anchor=tk.W, padding=2)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.populate()
        self.update_codes()

    def select_all(self, event: tk.Event) -> str:
        event.widget.selection_range(0, tk.END)
        return "break"

    def on_filter_changed(self, *_args: object) -> None:
        text = self.filter_var.get()
        if text:
            self.filtered = [
                (r, t) for (r, t) in self.items
                if r in search_records([r for r, _ in self.items], text)
            ]
        else:
            self.filtered = list(self.items)
        self.populate()

    def _iid(self, rec: TOTPRecord) -> str:
        return rec.uuid if rec.uuid else f"_auto_{id(rec)}"

    def populate(self) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)
        for rec, totp in self.filtered:
            code = totp.now()
            secs = remaining_secs(totp)
            self.tree.insert("", tk.END, iid=self._iid(rec), values=(
                rec.name,
                rec.issuer or "",
                code,
                f"{secs}s",
            ))

    def update_codes(self) -> None:
        for rec, totp_ in self.filtered:
            iid = self._iid(rec)
            if self.tree.exists(iid):
                code = totp_.now()
                secs = remaining_secs(totp_)
                self.tree.set(iid, "code", code)
                self.tree.set(iid, "remaining", f"{secs}s")
        self.root.after(1000, self.update_codes)

    def _copy_clipboard_persist(self, text: str) -> None:
        if hasattr(self, "_clip_proc") and self._clip_proc is not None:
            try:
                self._clip_proc.kill()
                self._clip_proc.wait(timeout=2)
            except Exception:
                pass
            self._clip_proc = None

        import platform
        os_name = platform.system()

        try:
            if os_name == "Linux":
                self._clip_proc = subprocess.Popen(
                    ["xclip", "-selection", "clipboard", "-loops", "0"],
                    stdin=subprocess.PIPE,
                )
                self._clip_proc.stdin.write(text.encode())
                self._clip_proc.stdin.close()
            elif os_name == "Darwin":
                subprocess.run(
                    ["pbcopy"], input=text, text=True, check=True,
                    timeout=5,
                )
            elif os_name == "Windows":
                subprocess.run(
                    ["clip"], input=text, text=True, check=True,
                    timeout=5,
                )
        except Exception:
            pass

    def on_item_click(self, event: tk.Event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return

        code = self.tree.set(iid, "code")
        self.root.clipboard_clear()
        self.root.clipboard_append(code)
        self._copy_clipboard_persist(code)
        self.status_var.set(f"Copied {code}")

    def on_delete(self) -> None:
        selected = set(self.tree.selection())
        if not selected:
            return
        kept = [(r, t) for (r, t) in self.items
                if self._iid(r) not in selected]
        removed = len(self.items) - len(kept)
        self.items = kept
        self.records = [r for r, _ in self.items]
        self.filtered = list(self.items)
        self.filter_var.set("")
        self.populate()
        self.status_var.set(f"Deleted {removed} record(s)")

    def on_add(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Select QR code image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            img = Image.open(path)
            decoded = qr_decode(img)
        except Exception as e:
            messagebox.showerror(
                "Read error", f"Could not read image:\n{e}",
                parent=self.root)
            return

        if not decoded:
            messagebox.showerror(
                "No QR code",
                "No QR code found in the selected image.",
                parent=self.root)
            return

        uri = decoded[0].data.decode()
        if not uri.startswith("otpauth://totp/"):
            messagebox.showerror(
                "Invalid QR code",
                "The QR code does not contain a valid TOTP URI.",
                parent=self.root)
            return

        try:
            new_rec = self._parse_otpauth(uri)
        except Exception as e:
            messagebox.showerror(
                "Parse error", f"Could not parse TOTP URI:\n{e}",
                parent=self.root)
            return

        self.records.append(new_rec)
        totp = create_totp(new_rec)
        self.items.append((new_rec, totp))
        self.filtered = list(self.items)
        self.filter_var.set("")
        self.populate()
        self.status_var.set(
            f"Added record for {new_rec.name}")

    @staticmethod
    def _parse_otpauth(uri: str) -> TOTPRecord:
        parsed = urlparse(uri)
        params = parse_qs(parsed.query)

        label = unquote(parsed.path.lstrip("/"))
        if ":" in label:
            issuer_from_label, name = label.split(":", 1)
        else:
            name = label
            issuer_from_label = None

        secret = params.get("secret", [""])[0]
        if not secret:
            raise ValueError("URI missing 'secret' parameter")

        issuer = params.get("issuer", [None])[0] or issuer_from_label
        digits = int(params.get("digits", ["6"])[0])
        period = int(params.get("period", ["30"])[0])

        return TOTPRecord(
            name=name,
            secret=secret,
            issuer=issuer,
            digits=digits,
            period=period,
            uuid=str(uuid.uuid4()),
        )

    def on_import(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Import from JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            candidates = import_json(path)
        except Exception:
            messagebox.showerror(
                "Import error",
                "Import failed. Only Aegis plaintext JSON is supported.",
                parent=self.root)
            return

        existing_uuids = {r.uuid for r in self.records if r.uuid}

        new_records = []
        skipped = 0
        for r in candidates:
            if r.uuid and r.uuid in existing_uuids:
                skipped += 1
                continue
            new_records.append(r)
            if r.uuid:
                existing_uuids.add(r.uuid)

        if not new_records:
            self.status_var.set(
                f"0 new imported, {skipped} existing skipped")
            return

        self.records.extend(new_records)
        self.items.extend((r, create_totp(r)) for r in new_records)
        self.filtered = list(self.items)
        self.filter_var.set("")
        self.populate()
        self.status_var.set(
            f"{len(new_records)} new imported, {skipped} existing skipped")

    def on_export(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export to JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            export_json(self.records, path)
        except Exception as e:
            messagebox.showerror("Export error", str(e), parent=self.root)
            return
        self.status_var.set(
            f"{len(self.records)} records exported")

    def on_quit(self) -> None:
        try:
            shutil.copy2("vault.csv", "vault.csv~")
        except Exception:
            pass

        try:
            store_records(self.records, "vault.csv", self.password)
        except Exception:
            pass

        if hasattr(self, "_clip_proc") and self._clip_proc is not None:
            try:
                self._clip_proc.kill()
            except Exception:
                pass
        self.root.destroy()


def ask_password() -> str | None:
    root = tk.Tk()
    root.withdraw()
    pw = simpledialog.askstring("Unlock vault", "Password:",
                                parent=root, show="*")
    root.destroy()
    return pw


def ask_new_password() -> str | None:
    dialog = tk.Tk()
    dialog.title("New vault")
    dialog.resizable(False, False)

    tk.Label(dialog, text="Choose a vault password:").grid(
        row=0, column=0, padx=10, pady=(10, 0), sticky=tk.W)
    pw1 = tk.Entry(dialog, show="*", width=30)
    pw1.grid(row=0, column=1, padx=(0, 10), pady=(10, 0))

    tk.Label(dialog, text="Confirm password:").grid(
        row=1, column=0, padx=10, pady=(5, 0), sticky=tk.W)
    pw2 = tk.Entry(dialog, show="*", width=30)
    pw2.grid(row=1, column=1, padx=(0, 10), pady=(5, 0))

    result: list[str | None] = [None]

    def ok() -> None:
        p1 = pw1.get()
        p2 = pw2.get()
        if not p1:
            return
        if p1 != p2:
            tk.Label(dialog, text="Passwords do not match",
                     fg="red").grid(row=2, column=0, columnspan=2, pady=5)
            return
        result[0] = p1
        dialog.destroy()

    def cancel() -> None:
        dialog.destroy()

    btn_frame = tk.Frame(dialog)
    btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
    tk.Button(btn_frame, text="OK", width=10, command=ok).pack(
        side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="Cancel", width=10, command=cancel).pack(
        side=tk.LEFT, padx=5)

    dialog.bind("<Return>", lambda e: ok())
    dialog.bind("<Escape>", lambda e: cancel())

    pw1.focus()
    dialog.grab_set()
    dialog.wait_window()

    return result[0]


def main() -> None:
    is_new = not Path("vault.csv").is_file()

    if is_new:
        pw = ask_new_password()
        if pw is None:
            return
        records = load_records("vault.csv", pw)
    else:
        while True:
            pw = ask_password()
            if pw is None:
                return
            try:
                records = load_records("vault.csv", pw)
            except InvalidToken:
                messagebox.showerror("Wrong password",
                                     "The password you entered is incorrect.")
                continue
            break

    root = tk.Tk()
    TOTPApp(root, records, pw)
    root.mainloop()


if __name__ == "__main__":
    main()

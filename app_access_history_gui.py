#!/usr/bin/env python3
"""Small Tkinter front-end for App Access History. Double-click or run:  python app_access_history_gui.py"""
import os
import queue
import sys
import threading
import webbrowser
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk  # noqa: E402
from tkinter import filedialog, messagebox, ttk  # noqa: E402

from app_access_history import cli  # noqa: E402
from app_access_history import engine as E  # noqa: E402

# Same dark palette as the HTML report
C = dict(bg="#121211", surface="#1a1a19", surface2="#232321", line="#33332f", text="#f0efec", text2="#c3c2b7",
         muted="#8f8e86", accent="#3987e5", accent_hover="#5a9cec", accent_soft="#1d2b3d", ok="#6cc678",
         bad="#ef7a73", warn="#e5a84a")
FONT = "Segoe UI"


class _QueueWriter:
    def __init__(self, q):
        self.q = q

    def write(self, s):
        if s:
            self.q.put(s)

    def flush(self):
        pass


def _sharp_text_on_windows():
    """Tell Windows the window handles display scaling itself, so text is not blurred."""
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass


class App(tk.Tk):
    def __init__(self):
        _sharp_text_on_windows()
        super().__init__()
        self.title(f"{E.TOOL_NAME} {E.TOOL_VERSION} - Capability Access Manager forensics")
        self.configure(bg=C["bg"])
        self.q: queue.Queue = queue.Queue()
        self.out_dir = None
        self.running = False

        self.ev = tk.StringVar()
        self.out = tk.StringVar()
        self.tz = tk.StringVar(value="+05:30")
        self.reg = tk.StringVar(value="none")
        self.regfile = tk.StringVar()
        self.hashbin = tk.BooleanVar(value=False)
        self.amc = tk.StringVar()

        self._style()
        self._header()

        body = ttk.Frame(self, padding=(18, 12, 18, 16))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3, uniform="col")
        body.columnconfigure(1, weight=2, uniform="col")
        body.rowconfigure(3, weight=1)

        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.columnconfigure(0, weight=1)

        # 1. evidence
        c1 = self._card(left, 0, "1", "Evidence folder",
                        "The folder you exported: CapabilityAccessManager.db and/or CapabilityConsentStorage.db, "
                        "with their -wal and -shm files (plus .FileSlack and $I30 if your tool exported them). "
                        "NTUSER.DAT or SOFTWARE hives in the same folder are used too. "
                        "Nothing is changed: every file is hashed before and after the run.")
        self._path_row(c1, self.ev, self.pick_ev)
        self.found = self._hint(c1, "No folder chosen yet.")
        self.found.pack_configure(pady=(6, 0))
        self.ev.trace_add("write", lambda *_: self._check_evidence())

        # 2. output
        c2 = self._card(left, 1, "2", "Report folder",
                        "Where the HTML report, Excel workbook and CSV files are written. "
                        "It must be outside the evidence folder; a new folder is created if it does not exist.")
        self._path_row(c2, self.out, self.pick_out)

        # what the run produces
        left.rowconfigure(2, weight=1)
        c4 = ttk.Frame(left, style="Card.TFrame", padding=(14, 10, 14, 12))
        c4.grid(row=2, column=0, sticky="nsew")
        ttk.Label(c4, text="What you get", style="CardTitle.TLabel").pack(anchor="w")
        for line in ("Activity timeline: which app used which service, start, end, duration and account.",
                     "Apps, services and permission settings, with who allowed or blocked what.",
                     "Recovered records: deleted rows and history hidden in the -wal and free space.",
                     "AppAccessHistory_report.html to open in any browser, plus Excel and CSV files."):
            self._hint(c4, "•  " + line).pack_configure(pady=(4, 0))

        # 3. options
        c3 = self._card(body, 0, "3", "Options", "All optional. The defaults are fine for a first look.", column=1)

        self._field(c3, "Local time offset")
        ttk.Entry(c3, textvariable=self.tz, width=9).pack(anchor="w")
        self._hint(c3, "e.g. +05:30 for India, +00:00 for UTC. The report always shows UTC as well.")

        self._field(c3, "Registry check")
        rf = ttk.Frame(c3, style="Card.TFrame")
        rf.pack(fill="x")
        for v, t in (("none", "Off"), ("live", "This PC (live)"), ("file", ".reg export")):
            ttk.Radiobutton(rf, text=t, value=v, variable=self.reg).pack(side="left", padx=(0, 12))
        self._path_row(c3, self.regfile, self.pick_reg, pady=(4, 0))
        self._hint(c3, "Compares each app's allow/deny setting and last-use time with the ConsentStore registry. "
                       "Use \"This PC\" only when the evidence came from this computer.")

        self._field(c3, "Amcache CSV")
        self._path_row(c3, self.amc, self.pick_amc)
        self._hint(c3, "Output of AmcacheParser. Matches program file hashes (FileID) with Amcache entries.")

        ttk.Checkbutton(c3, text="Hash program files on this PC", variable=self.hashbin).pack(anchor="w", pady=(10, 0))
        self._hint(c3, "SHA-1 of the first 30 MiB of each program, compared with the FileID in the database.")

        # actions
        bf = ttk.Frame(body)
        bf.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(2, 10))
        self.run_btn = ttk.Button(bf, text="Run analysis", style="Accent.TButton", command=self.run)
        self.run_btn.pack(side="left")
        self.open_btn = ttk.Button(bf, text="Open report", command=self.open_report, state="disabled")
        self.open_btn.pack(side="left", padx=8)
        ttk.Button(bf, text="Open report folder", command=self.open_folder).pack(side="left")
        self.status = ttk.Label(bf, text="Ready", style="Status.TLabel")
        self.status.pack(side="right")

        # progress log
        lf = ttk.Frame(body, style="Card.TFrame", padding=(14, 10, 14, 12))
        lf.grid(row=3, column=0, columnspan=2, sticky="nsew")
        ttk.Label(lf, text="Progress", style="CardTitle.TLabel").pack(anchor="w")
        self._hint(lf, "Each evidence file with its size and SHA-256, what was found, and the final integrity check.")
        holder = ttk.Frame(lf, style="Card.TFrame")
        holder.pack(fill="both", expand=True)
        self.log = tk.Text(holder, height=10, wrap="none", font=("Consolas", 9), bg=C["bg"], fg=C["text2"],
                           insertbackground=C["text"], relief="flat", highlightthickness=1,
                           highlightbackground=C["line"], highlightcolor=C["line"], padx=8, pady=6)
        sb = ttk.Scrollbar(holder, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)
        self._fit_to_screen()
        self.after(100, self.drain)

    # ---- look -------------------------------------------------------------------------------------------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["text"], font=(FONT, 10), bordercolor=C["line"],
                    lightcolor=C["line"], darkcolor=C["line"], troughcolor=C["surface2"], focuscolor=C["accent"])
        s.configure("TFrame", background=C["bg"])
        s.configure("Card.TFrame", background=C["surface"])
        s.configure("Header.TFrame", background=C["surface"])
        s.configure("TLabel", background=C["bg"], foreground=C["text"])
        s.configure("Brand.TLabel", background=C["surface"], foreground=C["text"], font=(FONT, 16, "bold"))
        s.configure("Sub.TLabel", background=C["surface"], foreground=C["muted"], font=(FONT, 10))
        s.configure("Chip.TLabel", background=C["accent_soft"], foreground=C["accent_hover"], font=(FONT, 9, "bold"),
                    padding=(10, 4))
        s.configure("CardTitle.TLabel", background=C["surface"], foreground=C["text"], font=(FONT, 11, "bold"))
        s.configure("Step.TLabel", background=C["accent"], foreground="#ffffff", font=(FONT, 9, "bold"),
                    padding=(7, 1), anchor="center")
        s.configure("Hint.TLabel", background=C["surface"], foreground=C["muted"], font=(FONT, 9))
        s.configure("Field.TLabel", background=C["surface"], foreground=C["text2"])
        s.configure("Ok.TLabel", background=C["surface"], foreground=C["ok"], font=(FONT, 9))
        s.configure("Warn.TLabel", background=C["surface"], foreground=C["warn"], font=(FONT, 9))
        s.configure("Status.TLabel", background=C["bg"], foreground=C["muted"], font=(FONT, 10, "bold"))
        s.configure("TEntry", fieldbackground=C["bg"], foreground=C["text"], insertcolor=C["text"],
                    bordercolor=C["line"], lightcolor=C["line"], darkcolor=C["line"], padding=(6, 5))
        s.map("TEntry", bordercolor=[("focus", C["accent"])], lightcolor=[("focus", C["accent"])])
        s.configure("TButton", background=C["surface2"], foreground=C["text"], padding=(12, 6), borderwidth=1,
                    bordercolor=C["line"], lightcolor=C["surface2"], darkcolor=C["surface2"])
        s.map("TButton", background=[("disabled", C["surface"]), ("active", C["line"])],
              foreground=[("disabled", C["muted"])])
        s.configure("Accent.TButton", background=C["accent"], foreground="#ffffff", font=(FONT, 10, "bold"),
                    padding=(18, 7), bordercolor=C["accent"], lightcolor=C["accent"], darkcolor=C["accent"])
        s.map("Accent.TButton", background=[("disabled", C["accent_soft"]), ("active", C["accent_hover"])],
              foreground=[("disabled", C["muted"])])
        for w in ("TRadiobutton", "TCheckbutton"):
            s.configure(w, background=C["surface"], foreground=C["text2"], indicatorbackground=C["bg"],
                        indicatorforeground=C["accent"], bordercolor=C["line"])
            s.map(w, background=[("active", C["surface"])], foreground=[("active", C["text"])],
                  indicatorbackground=[("selected", C["accent"]), ("active", C["surface2"])])
        s.configure("Vertical.TScrollbar", background=C["surface2"], arrowcolor=C["muted"], bordercolor=C["surface"])

    def _header(self):
        h = ttk.Frame(self, style="Header.TFrame", padding=(18, 12))
        h.pack(fill="x")
        logo = tk.Canvas(h, width=36, height=36, bg=C["surface"], highlightthickness=0)
        logo.create_rectangle(2, 2, 34, 34, fill=C["accent"], outline=C["accent"])
        logo.create_polygon(18, 9, 27, 12, 27, 19, 18, 28, 9, 19, 9, 12, fill="", outline="#ffffff", width=2)
        logo.pack(side="left")
        t = ttk.Frame(h, style="Header.TFrame")
        t.pack(side="left", padx=12)
        ttk.Label(t, text=E.TOOL_NAME, style="Brand.TLabel").pack(anchor="w")
        ttk.Label(t, text=f"Which app used which service, when, and for how long · version {E.TOOL_VERSION}",
                  style="Sub.TLabel").pack(anchor="w")
        ttk.Label(h, text="READ-ONLY · EVIDENCE NEVER CHANGED", style="Chip.TLabel").pack(side="right")
        tk.Frame(self, height=1, bg=C["line"]).pack(fill="x")

    def _card(self, parent, row, step, title, hint, column=0):
        card = ttk.Frame(parent, style="Card.TFrame", padding=(14, 10, 14, 12))
        card.grid(row=row, column=column, sticky="nsew", pady=(0, 10))
        top = ttk.Frame(card, style="Card.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text=step, style="Step.TLabel").pack(side="left")
        ttk.Label(top, text=title, style="CardTitle.TLabel").pack(side="left", padx=8)
        self._hint(card, hint).pack_configure(pady=(4, 8))
        return card

    def _hint(self, parent, text):
        """Muted help text that wraps to the width it is given."""
        lab = ttk.Label(parent, text=text, style="Hint.TLabel", justify="left")
        lab.pack(fill="x", anchor="w")
        lab.bind("<Configure>", lambda e: lab.configure(wraplength=max(e.width - 4, 100)))
        return lab

    def _field(self, parent, text):
        ttk.Label(parent, text=text, style="Field.TLabel").pack(anchor="w", pady=(10, 4))

    def _path_row(self, parent, var, cmd, pady=(0, 0)):
        r = ttk.Frame(parent, style="Card.TFrame")
        r.pack(fill="x", pady=pady)
        ttk.Entry(r, textvariable=var).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(r, text="Browse…", command=cmd).pack(side="left")

    def _fit_to_screen(self):
        """Open at a comfortable size for the screen's scaling, never taller than the screen."""
        f = float(self.tk.call("tk", "scaling")) / (96 / 72)
        w = min(int(1180 * f), self.winfo_screenwidth() - 40)
        h = min(int(820 * f), self.winfo_screenheight() - 90)
        self.geometry(f"{w}x{h}+{max((self.winfo_screenwidth() - w) // 2, 0)}+10")
        self.minsize(min(int(900 * f), w), min(int(620 * f), h))

    def _check_evidence(self):
        d = self.ev.get().strip()
        if not d:
            self.found.configure(text="No folder chosen yet.", style="Hint.TLabel")
            return
        if not os.path.isdir(d):
            self.found.configure(text="Folder not found.", style="Warn.TLabel")
            return
        try:
            roles = E.discover(d)
        except OSError as ex:
            self.found.configure(text=f"Cannot read this folder: {ex}", style="Warn.TLabel")
            return
        dbs = [r for r in roles if r.startswith(("CapabilityAccessManager", "CapabilityConsentStorage"))]
        if not any(r.endswith(".db") for r in dbs):
            self.found.configure(text="No CapabilityAccessManager.db or CapabilityConsentStorage.db in this folder.",
                                 style="Warn.TLabel")
            return
        extra = [r.split(":")[0] for r in roles if r not in dbs]
        msg = "Found: " + ", ".join(dbs + extra)
        if any(r.endswith(".db") and r + "-wal" not in roles for r in dbs):
            msg += "    (no -wal file next to a database: the newest activity may be missing)"
            self.found.configure(text=msg, style="Warn.TLabel")
        else:
            self.found.configure(text=msg, style="Ok.TLabel")

    # ---- actions ----------------------------------------------------------------------------------------
    def pick_ev(self):
        d = filedialog.askdirectory(title="Folder with CapabilityAccessManager.db")
        if d:
            self.ev.set(d)
            if not self.out.get():
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                self.out.set(os.path.join(os.path.dirname(d), f"app_access_history_output_{stamp}"))

    def pick_out(self):
        d = filedialog.askdirectory(title="Report folder")
        if d:
            self.out.set(d)

    def pick_reg(self):
        f = filedialog.askopenfilename(filetypes=[("Registry export", "*.reg"), ("All", "*.*")])
        if f:
            self.regfile.set(f)
            self.reg.set("file")

    def pick_amc(self):
        f = filedialog.askopenfilename(filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if f:
            self.amc.set(f)

    def run(self):
        if self.running:
            return
        if not self.ev.get():
            messagebox.showerror(E.TOOL_NAME, "Choose the evidence folder first.")
            return
        args = [self.ev.get(), "--tz", self.tz.get() or "+00:00"]
        if self.out.get():
            args += ["-o", self.out.get()]
        if self.reg.get() == "live":
            args += ["--registry", "live"]
        elif self.reg.get() == "file" and self.regfile.get():
            args += ["--registry", self.regfile.get()]
        if self.hashbin.get():
            args.append("--hash-binaries")
        if self.amc.get():
            args += ["--amcache-csv", self.amc.get()]
        self.log.delete("1.0", "end")
        self.running = True
        self.out_dir = None
        self.open_btn.configure(state="disabled")
        self.run_btn.configure(state="disabled")
        self.status.configure(text="Running…", foreground=C["accent_hover"])
        threading.Thread(target=self._worker, args=(args,), daemon=True).start()

    def _worker(self, args):
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = _QueueWriter(self.q)
        rc = 1
        try:
            rc = cli.main(args)
        except SystemExit as ex:
            rc = ex.code
        except Exception as ex:  # shown to the user, never swallowed
            self.q.put(f"\nERROR: {type(ex).__name__}: {ex}\n")
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        self.q.put(("__done__", rc))

    def drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, tuple) and item[0] == "__done__":
                    self.running = False
                    self.run_btn.configure(state="normal")
                    rc = item[1]
                    text, colour = {0: ("Done · evidence unchanged", C["ok"]),
                                    2: ("Stopped · see the message below", C["warn"]),
                                    3: ("INTEGRITY FAILURE", C["bad"])}.get(rc, (f"Finished (code {rc})", C["warn"]))
                    self.status.configure(text=text, foreground=colour)
                    txt = self.log.get("1.0", "end")
                    for line in txt.splitlines():
                        if line.startswith("Report: "):
                            self.out_dir = os.path.dirname(line[8:].strip())
                    if self.out_dir:
                        self.open_btn.configure(state="normal")
                else:
                    self.log.insert("end", item)
                    self.log.see("end")
        except queue.Empty:
            pass
        self.after(100, self.drain)

    def open_report(self):
        if self.out_dir:
            webbrowser.open("file:///" + os.path.join(self.out_dir, "AppAccessHistory_report.html").replace("\\", "/"))

    def open_folder(self):
        d = self.out_dir or self.out.get()
        if d and os.path.isdir(d):
            os.startfile(d) if hasattr(os, "startfile") else webbrowser.open(d)


if __name__ == "__main__":
    App().mainloop()

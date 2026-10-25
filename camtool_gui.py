#!/usr/bin/env python3
"""Small Tkinter front-end for WinWitness. Double-click or run:  python camtool_gui.py"""
import os
import queue
import sys
import threading
import webbrowser
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk  # noqa: E402
from tkinter import filedialog, messagebox, ttk  # noqa: E402

from camtool import cli  # noqa: E402
from camtool import engine as E  # noqa: E402


class _QueueWriter:
    def __init__(self, q):
        self.q = q

    def write(self, s):
        if s:
            self.q.put(s)

    def flush(self):
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{E.TOOL_NAME} {E.TOOL_VERSION} - Capability Access Manager forensics")
        self.geometry("900x620")
        self.minsize(640, 420)
        self.q: queue.Queue = queue.Queue()
        self.out_dir = None
        self.running = False

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        self.ev = tk.StringVar()
        self.out = tk.StringVar()
        self.tz = tk.StringVar(value="+05:30")
        self.reg = tk.StringVar(value="none")
        self.regfile = tk.StringVar()
        self.hashbin = tk.BooleanVar(value=False)
        self.amc = tk.StringVar()

        def row(r, label, var, cmd=None, btn="Browse…"):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="w", pady=3)
            ttk.Entry(frm, textvariable=var).grid(row=r, column=1, sticky="ew", padx=6)
            if cmd:
                ttk.Button(frm, text=btn, command=cmd).grid(row=r, column=2)

        row(0, "Evidence folder", self.ev, self.pick_ev)
        row(1, "Output folder", self.out, self.pick_out)
        row(2, "Local time offset", self.tz)
        rf = ttk.Frame(frm)
        rf.grid(row=3, column=0, columnspan=3, sticky="w", pady=4)
        ttk.Label(rf, text="Registry corroboration:").pack(side="left")
        for v, t in (("none", "none"), ("live", "this PC (live)"), ("file", ".reg file")):
            ttk.Radiobutton(rf, text=t, value=v, variable=self.reg).pack(side="left", padx=4)
        ttk.Entry(rf, textvariable=self.regfile, width=40).pack(side="left", padx=4)
        ttk.Button(rf, text="…", width=3, command=self.pick_reg).pack(side="left")
        row(4, "Amcache CSV (optional)", self.amc, self.pick_amc)
        ttk.Checkbutton(frm, text="Hash binaries on this PC (SHA-1 of first 30 MiB, compare with FileID)",
                        variable=self.hashbin).grid(row=5, column=0, columnspan=3, sticky="w")
        bf = ttk.Frame(frm)
        bf.grid(row=6, column=0, columnspan=3, sticky="w", pady=8)
        self.run_btn = ttk.Button(bf, text="Run analysis", command=self.run)
        self.run_btn.pack(side="left")
        self.open_btn = ttk.Button(bf, text="Open report", command=self.open_report, state="disabled")
        self.open_btn.pack(side="left", padx=6)
        ttk.Button(bf, text="Open output folder", command=self.open_folder).pack(side="left")
        self.status = ttk.Label(bf, text="")
        self.status.pack(side="left", padx=12)
        self.log = tk.Text(frm, height=20, wrap="none", font=("Consolas", 9))
        self.log.grid(row=7, column=0, columnspan=3, sticky="nsew")
        frm.rowconfigure(7, weight=1)
        sb = ttk.Scrollbar(frm, command=self.log.yview)
        sb.grid(row=7, column=3, sticky="ns")
        self.log.configure(yscrollcommand=sb.set)
        self.after(100, self.drain)

    def pick_ev(self):
        d = filedialog.askdirectory(title="Folder with CapabilityAccessManager.db")
        if d:
            self.ev.set(d)
            if not self.out.get():
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                self.out.set(os.path.join(os.path.dirname(d), f"camtool_output_{stamp}"))

    def pick_out(self):
        d = filedialog.askdirectory(title="Output folder")
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
            messagebox.showerror("WinWitness", "Choose the evidence folder first.")
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
        self.run_btn.configure(state="disabled")
        self.status.configure(text="running…")
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
                    self.status.configure(text={0: "done - inputs unchanged", 2: "nothing to analyse",
                                                3: "INTEGRITY FAILURE"}.get(rc, f"finished (code {rc})"))
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
            webbrowser.open("file:///" + os.path.join(self.out_dir, "CAM_report.html").replace("\\", "/"))

    def open_folder(self):
        d = self.out_dir or self.out.get()
        if d and os.path.isdir(d):
            os.startfile(d) if hasattr(os, "startfile") else webbrowser.open(d)


if __name__ == "__main__":
    App().mainloop()

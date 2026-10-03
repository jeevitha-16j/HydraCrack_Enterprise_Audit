#!/usr/bin/env python3
"""
HydraCrack GUI - Tkinter front-end for live demos during review presentation.
Run: python3 hydracrack_gui.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import string

from hydracrack import HydraCrack, detect_algorithm, SUPPORTED_ALGOS


class HydraCrackGUI:
    def __init__(self, root):
        self.root = root
        root.title("HydraCrack - Multi-Threaded Hash Cracking Tool")
        root.geometry("640x560")
        root.configure(bg="#0d1117")

        title = tk.Label(root, text="HydraCrack", font=("Consolas", 22, "bold"),
                          fg="#58a6ff", bg="#0d1117")
        title.pack(pady=(15, 0))
        sub = tk.Label(root, text="Multi-Threaded Hash Cracking Tool  |  by Jeevitha M",
                        font=("Consolas", 10), fg="#8b949e", bg="#0d1117")
        sub.pack(pady=(0, 15))

        form = tk.Frame(root, bg="#0d1117")
        form.pack(fill="x", padx=20)

        self._label(form, "Target Hash:")
        self.hash_entry = tk.Entry(form, width=60, bg="#161b22", fg="#c9d1d9", insertbackground="white")
        self.hash_entry.pack(fill="x", pady=(0, 8))

        self._label(form, "Algorithm (leave blank for auto-detect):")
        self.algo_var = tk.StringVar(value="auto")
        algo_menu = ttk.Combobox(form, textvariable=self.algo_var,
                                  values=["auto"] + list(SUPPORTED_ALGOS.keys()), state="readonly")
        algo_menu.pack(fill="x", pady=(0, 8))

        self._label(form, "Mode:")
        self.mode_var = tk.StringVar(value="dictionary")
        mode_frame = tk.Frame(form, bg="#0d1117")
        mode_frame.pack(fill="x", pady=(0, 8))
        tk.Radiobutton(mode_frame, text="Dictionary Attack", variable=self.mode_var, value="dictionary",
                        bg="#0d1117", fg="#c9d1d9", selectcolor="#161b22").pack(side="left", padx=5)
        tk.Radiobutton(mode_frame, text="Brute-Force Attack", variable=self.mode_var, value="brute",
                        bg="#0d1117", fg="#c9d1d9", selectcolor="#161b22").pack(side="left", padx=5)

        self._label(form, "Wordlist file:")
        wl_frame = tk.Frame(form, bg="#0d1117")
        wl_frame.pack(fill="x", pady=(0, 8))
        self.wordlist_entry = tk.Entry(wl_frame, bg="#161b22", fg="#c9d1d9", insertbackground="white")
        self.wordlist_entry.pack(side="left", fill="x", expand=True)
        tk.Button(wl_frame, text="Browse", command=self.browse_wordlist).pack(side="left", padx=5)

        self._label(form, "Threads:")
        self.threads_var = tk.IntVar(value=8)
        tk.Scale(form, from_=1, to=32, orient="horizontal", variable=self.threads_var,
                 bg="#0d1117", fg="#c9d1d9", troughcolor="#161b22", highlightthickness=0).pack(fill="x")

        self.crack_btn = tk.Button(root, text="⚡ Start Cracking", font=("Consolas", 12, "bold"),
                                    bg="#238636", fg="white", command=self.start_crack)
        self.crack_btn.pack(pady=15)

        self.output = tk.Text(root, height=12, bg="#010409", fg="#39d353", font=("Consolas", 10))
        self.output.pack(fill="both", expand=True, padx=20, pady=(0, 15))

    def _label(self, parent, text):
        tk.Label(parent, text=text, font=("Consolas", 10), fg="#c9d1d9", bg="#0d1117", anchor="w").pack(fill="x")

    def browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def log(self, msg):
        self.output.insert(tk.END, msg + "\n")
        self.output.see(tk.END)
        self.output.update()

    def start_crack(self):
        self.crack_btn.config(state="disabled")
        threading.Thread(target=self._run_crack, daemon=True).start()

    def _run_crack(self):
        self.output.delete("1.0", tk.END)
        target_hash = self.hash_entry.get().strip()
        if not target_hash:
            messagebox.showerror("Error", "Please enter a target hash.")
            self.crack_btn.config(state="normal")
            return

        algo = None if self.algo_var.get() == "auto" else self.algo_var.get()
        threads = self.threads_var.get()

        try:
            cracker = HydraCrack(target_hash, algo=algo, threads=threads, verbose=False)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            self.crack_btn.config(state="normal")
            return

        self.log(f"[*] Target hash : {cracker.target_hash}")
        self.log(f"[*] Algorithm   : {cracker.algo.upper()}")
        self.log(f"[*] Threads     : {threads}")
        self.log("[*] Cracking in progress...\n")

        if self.mode_var.get() == "dictionary":
            wl = self.wordlist_entry.get().strip()
            if not wl:
                messagebox.showerror("Error", "Please choose a wordlist file.")
                self.crack_btn.config(state="normal")
                return
            report = cracker.dictionary_attack(wl)
        else:
            report = cracker.brute_force_attack(string.ascii_lowercase + string.digits, 1, 5)

        if report["cracked"]:
            self.log(f"[+] HASH CRACKED! Plaintext = '{report['plaintext']}'")
        else:
            self.log("[-] Hash NOT cracked with given parameters.")
        self.log(f"[+] Attempts : {report['attempts']:,}")
        self.log(f"[+] Time     : {report['time_seconds']}s")
        self.log(f"[+] Speed    : {report['speed_hps']:,} hashes/sec")

        self.crack_btn.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = HydraCrackGUI(root)
    root.mainloop()

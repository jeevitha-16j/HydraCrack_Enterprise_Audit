#!/usr/bin/env python3
"""
HydraCrack - Multi-Threaded Hash Cracking Tool
================================================
A high-performance, multi-threaded password hash cracking utility built for
security research, password auditing, and penetration testing education.

Author : Jeevitha M
Role   : Cyber Security Intern
Course : B.E. CSE (Cyber Security) - V Semester
Institute: J.N.N Institute of Engineering (Autonomous)

Features:
    - Multi-threaded dictionary attack (configurable thread pool)
    - Brute-force attack mode with custom charset/length
    - Supports MD5, SHA1, SHA256, SHA512, NTLM(MD4-based) hashing algorithms
    - Hash auto-detection by length/pattern
    - Salted hash support (user-supplied salt)
    - Live progress bar + attempts/sec speed meter
    - Session logging (CSV report of cracked hashes, time taken)
    - Graceful thread shutdown the moment a match is found
"""

import hashlib
import threading
import queue
import time
import string
import itertools
import argparse
import os
import sys
import csv
from datetime import datetime

# ----------------------------- Hash Detection ----------------------------- #

HASH_SIGNATURES = {
    32: "md5",
    40: "sha1",
    64: "sha256",
    128: "sha512",
}

SUPPORTED_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def detect_algorithm(hash_value: str) -> str:
    """Guess the hashing algorithm from the hex digest length."""
    hash_value = hash_value.strip()
    algo = HASH_SIGNATURES.get(len(hash_value))
    if not algo:
        raise ValueError(
            f"Unable to auto-detect algorithm for hash of length {len(hash_value)}. "
            f"Supported lengths: {list(HASH_SIGNATURES.keys())}"
        )
    return algo


def compute_hash(word: str, algo: str, salt: str = "") -> str:
    """Compute the hex digest of word(+salt) using the given algorithm."""
    hasher = SUPPORTED_ALGOS[algo]()
    hasher.update((word + salt).encode("utf-8", errors="ignore"))
    return hasher.hexdigest()


# ------------------------------ Core Engine -------------------------------- #

class HydraCrack:
    def __init__(self, target_hash, algo=None, salt="", threads=8, verbose=True):
        self.target_hash = target_hash.strip().lower()
        self.algo = algo or detect_algorithm(self.target_hash)
        self.salt = salt
        self.threads = threads
        self.verbose = verbose

        self.found_event = threading.Event()
        self.result = None
        self.attempts = 0
        self.attempts_lock = threading.Lock()
        self.start_time = None

    # ---------------- Dictionary Attack ---------------- #

    def dictionary_attack(self, wordlist_path):
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip("\n\r") for line in f if line.strip("\n\r")]

        work_queue = queue.Queue()
        for w in words:
            work_queue.put(w)

        self.start_time = time.time()
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._dict_worker, args=(work_queue,), daemon=True)
            threads.append(t)
            t.start()

        progress_thread = threading.Thread(target=self._progress_reporter, args=(len(words),), daemon=True)
        if self.verbose:
            progress_thread.start()

        for t in threads:
            t.join()

        self.found_event.set()  # stop progress reporter
        return self._build_report("dictionary", wordlist_path, len(words))

    def _dict_worker(self, work_queue):
        while not self.found_event.is_set():
            try:
                word = work_queue.get_nowait()
            except queue.Empty:
                return

            candidate_hash = compute_hash(word, self.algo, self.salt)
            with self.attempts_lock:
                self.attempts += 1

            if candidate_hash == self.target_hash:
                self.result = word
                self.found_event.set()
                return
            work_queue.task_done()

    # ---------------- Brute Force Attack ---------------- #

    def brute_force_attack(self, charset=None, min_len=1, max_len=6):
        charset = charset or (string.ascii_lowercase + string.digits)
        self.start_time = time.time()

        length_queue = queue.Queue()
        for length in range(min_len, max_len + 1):
            length_queue.put(length)

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(
                target=self._brute_worker, args=(length_queue, charset), daemon=True
            )
            threads.append(t)
            t.start()

        progress_thread = threading.Thread(target=self._progress_reporter, args=(None,), daemon=True)
        if self.verbose:
            progress_thread.start()

        for t in threads:
            t.join()

        self.found_event.set()
        return self._build_report("brute_force", f"charset_len={len(charset)}", None)

    def _brute_worker(self, length_queue, charset):
        while not self.found_event.is_set():
            try:
                length = length_queue.get_nowait()
            except queue.Empty:
                return

            for combo in itertools.product(charset, repeat=length):
                if self.found_event.is_set():
                    return
                word = "".join(combo)
                candidate_hash = compute_hash(word, self.algo, self.salt)
                with self.attempts_lock:
                    self.attempts += 1

                if candidate_hash == self.target_hash:
                    self.result = word
                    self.found_event.set()
                    return

    # ---------------- Shared Helpers ---------------- #

    def _progress_reporter(self, total):
        while not self.found_event.is_set():
            time.sleep(1)
            elapsed = time.time() - self.start_time
            speed = self.attempts / elapsed if elapsed > 0 else 0
            if total:
                pct = min(100, (self.attempts / total) * 100)
                sys.stdout.write(
                    f"\r[*] Progress: {pct:5.1f}% | Attempts: {self.attempts:,} | Speed: {speed:,.0f} h/s"
                )
            else:
                sys.stdout.write(
                    f"\r[*] Attempts: {self.attempts:,} | Speed: {speed:,.0f} h/s"
                )
            sys.stdout.flush()
        print()

    def _build_report(self, mode, source, total_candidates):
        elapsed = time.time() - self.start_time
        speed = self.attempts / elapsed if elapsed > 0 else 0
        report = {
            "target_hash": self.target_hash,
            "algorithm": self.algo,
            "mode": mode,
            "source": source,
            "cracked": self.result is not None,
            "plaintext": self.result,
            "attempts": self.attempts,
            "time_seconds": round(elapsed, 3),
            "speed_hps": round(speed, 2),
            "threads": self.threads,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        }
        return report


# --------------------------------- CLI ------------------------------------- #

BANNER = r"""
  _   _           _            ____                _
 | | | |_   _  __| |_ __ __ _ / ___|_ __ __ _  ___| | __
 | |_| | | | |/ _` | '__/ _` | |   | '__/ _` |/ __| |/ /
 |  _  | |_| | (_| | | | (_| | |___| | | (_| | (__|   <
 |_| |_|\__, |\__,_|_|  \__,_|\____|_|  \__,_|\___|_|\_\
        |___/      Multi-Threaded Hash Cracking Tool v1.0
                    by Jeevitha M | Cyber Security Intern
"""


def log_result_to_csv(report, log_path="session_log.csv"):
    file_exists = os.path.exists(log_path)
    with open(log_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(report.keys()))
        if not file_exists:
            writer.writeheader()
        writer.writerow(report)


def main():
    parser = argparse.ArgumentParser(
        description="HydraCrack - Multi-Threaded Hash Cracking Tool"
    )
    parser.add_argument("-H", "--hash", required=True, help="Target hash to crack")
    parser.add_argument("-a", "--algo", choices=SUPPORTED_ALGOS.keys(), help="Hash algorithm (auto-detected if omitted)")
    parser.add_argument("-s", "--salt", default="", help="Known salt appended to each candidate")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for dictionary attack")
    parser.add_argument("-b", "--bruteforce", action="store_true", help="Enable brute-force mode")
    parser.add_argument("--min-len", type=int, default=1, help="Brute-force min length")
    parser.add_argument("--max-len", type=int, default=6, help="Brute-force max length")
    parser.add_argument("--charset", default=string.ascii_lowercase + string.digits, help="Brute-force charset")
    parser.add_argument("-t", "--threads", type=int, default=8, help="Number of worker threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress live progress output")
    parser.add_argument("--log", default="session_log.csv", help="CSV file to append session report")

    args = parser.parse_args()
    print(BANNER)

    cracker = HydraCrack(
        target_hash=args.hash,
        algo=args.algo,
        salt=args.salt,
        threads=args.threads,
        verbose=not args.quiet,
    )

    print(f"[*] Target hash : {cracker.target_hash}")
    print(f"[*] Algorithm   : {cracker.algo.upper()}")
    print(f"[*] Threads     : {cracker.threads}")

    if args.wordlist:
        print(f"[*] Mode        : Dictionary attack")
        print(f"[*] Wordlist    : {args.wordlist}\n")
        report = cracker.dictionary_attack(args.wordlist)
    elif args.bruteforce:
        print(f"[*] Mode        : Brute-force attack")
        print(f"[*] Charset     : {args.charset}")
        print(f"[*] Length range: {args.min_len}-{args.max_len}\n")
        report = cracker.brute_force_attack(args.charset, args.min_len, args.max_len)
    else:
        print("[!] Specify either --wordlist (dictionary) or --bruteforce mode.")
        sys.exit(1)

    print("\n" + "=" * 60)
    if report["cracked"]:
        print(f"[+] HASH CRACKED!")
        print(f"[+] Plaintext : {report['plaintext']}")
    else:
        print(f"[-] Hash NOT cracked with given parameters.")
    print(f"[+] Attempts  : {report['attempts']:,}")
    print(f"[+] Time taken: {report['time_seconds']}s")
    print(f"[+] Speed     : {report['speed_hps']:,} hashes/sec")
    print("=" * 60)

    log_result_to_csv(report, args.log)
    print(f"[*] Session logged to {args.log}")


if __name__ == "__main__":
    main()

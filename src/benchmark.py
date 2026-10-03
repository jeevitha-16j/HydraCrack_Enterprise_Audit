#!/usr/bin/env python3
"""
benchmark.py
------------
Compares single-threaded vs multi-threaded cracking speed on the same
target hash + wordlist. Use this output as evidence/graph material for
your internship review report (shows WHY multi-threading matters).

Usage:
    python3 benchmark.py
"""

import time
import hashlib
from hydracrack import HydraCrack


def single_threaded_dictionary(target_hash, wordlist_path, algo="md5"):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    start = time.time()
    attempts = 0
    found = None
    for w in words:
        h = hashlib.new(algo, w.encode()).hexdigest()
        attempts += 1
        if h == target_hash:
            found = w
            break
    elapsed = time.time() - start
    return {"found": found, "attempts": attempts, "time": elapsed}


def run_benchmark(target_hash, wordlist_path, thread_counts=(1, 2, 4, 8, 16)):
    print(f"{'Threads':<10}{'Time (s)':<12}{'Speed (h/s)':<15}{'Result'}")
    print("-" * 55)

    # True single-threaded baseline (no thread overhead at all)
    baseline = single_threaded_dictionary(target_hash, wordlist_path)
    speed = baseline["attempts"] / baseline["time"] if baseline["time"] > 0 else 0
    print(f"{'1 (raw)':<10}{baseline['time']:<12.4f}{speed:<15.2f}{baseline['found']}")

    for t in thread_counts:
        cracker = HydraCrack(target_hash, threads=t, verbose=False)
        report = cracker.dictionary_attack(wordlist_path)
        print(f"{t:<10}{report['time_seconds']:<12.4f}{report['speed_hps']:<15.2f}{report['plaintext']}")


if __name__ == "__main__":
    import hashlib as _h
    # Use a word near the END of the wordlist so threads must do real work
    target = _h.md5(b"hydracrack").hexdigest()
    run_benchmark(target, "../wordlists/common_passwords.txt")

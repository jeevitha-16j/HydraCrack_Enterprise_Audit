#!/usr/bin/env python3
"""
generate_sample_hashes.py
--------------------------
Helper utility to generate sample hashes (from a given word, with an optional
salt) for demo/testing HydraCrack during your review presentation.

Usage:
    python3 generate_sample_hashes.py mypassword123
    python3 generate_sample_hashes.py mypassword123 --salt a1b2c3
"""

import hashlib
import argparse


def generate(word, salt=""):
    data = (word + salt).encode("utf-8")
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate sample hashes for HydraCrack demo")
    parser.add_argument("word", help="Plaintext word to hash")
    parser.add_argument("--salt", default="", help="Optional salt")
    args = parser.parse_args()

    hashes = generate(args.word, args.salt)
    print(f"Plaintext: {args.word}   Salt: '{args.salt}'\n")
    for algo, h in hashes.items():
        print(f"{algo.upper():8}: {h}")

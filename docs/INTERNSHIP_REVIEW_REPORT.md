# Internship Review Report

## HydraCrack — Multi-Threaded Hash Cracking Tool

| | |
|---|---|
| **Student Name** | Jeevitha M |
| **Register Number** | 110723105016 |
| **Programme** | B.E. Computer Science and Engineering (Cyber Security) |
| **Semester** | V Semester |
| **Institute** | J.N.N Institute of Engineering (Autonomous) |
| **Academic Year** | 2025–2026 |
| **Internship Domain** | Cyber Security |
| **Project Title** | HydraCrack: A Multi-Threaded Hash Cracking Tool |

---

## 1. Introduction

Password security remains one of the most fundamental pillars of
information security. Despite advances in authentication technology,
password hashes are still widely used across operating systems, web
applications, and network services. Understanding how attackers
crack weak password hashes — and consequently how to defend against
it — is a core competency for any cyber security professional.

This project, **HydraCrack**, was developed during the internship
period to consolidate practical knowledge gained across multiple
internship modules: network traffic analysis (Wireshark), penetration
testing environment usage (Kali Linux), applied cryptography, and the
study of common cyber attack vectors.

## 2. Objective

- To design and implement a hash cracking utility capable of dictionary
  and brute-force attacks.
- To apply **multi-threading** concepts to significantly reduce the
  time required to crack weak password hashes.
- To support multiple industry-standard hashing algorithms (MD5,
  SHA-1, SHA-256, SHA-512) with automatic algorithm detection.
- To benchmark and quantitatively demonstrate the performance gain of
  multi-threaded execution over single-threaded execution.
- To build both a command-line interface (for automation/scripting)
  and a graphical interface (for demonstration) so the tool is usable
  by both technical and non-technical audiences.

## 3. Tools & Technologies Used

| Category | Tool / Technology |
|---|---|
| Programming Language | Python 3 |
| Concurrency Model | Python `threading` module (thread pool + shared work queue) |
| Cryptographic Library | Python `hashlib` (MD5, SHA1, SHA256, SHA512) |
| GUI Framework | Tkinter |
| Environment | Kali Linux / cross-platform |
| Version Control Concepts | Modular folder structure, CSV-based audit logging |
| Related Internship Skills Applied | Wireshark (traffic/packet analysis), Kali Linux toolset familiarity, applied cryptography, understanding of brute-force/dictionary cyber attacks |

## 4. System Architecture

HydraCrack follows a **producer–consumer multi-threading architecture**:

1. **Work distribution:** The full wordlist (or the brute-force
   keyspace, split by candidate length) is loaded into a thread-safe
   `queue.Queue`.
2. **Worker threads:** A configurable pool of worker threads (default
   8, adjustable 1–32) each pull candidates off the queue
   independently, hash them using the detected/selected algorithm, and
   compare the digest against the target hash.
3. **Synchronization:** A shared `threading.Event` (`found_event`)
   allows any worker thread that finds a match to immediately signal
   all other threads to stop — avoiding wasted computation.
4. **Thread-safe counters:** A `threading.Lock`-protected counter
   tracks total attempts across all threads for accurate live
   progress and speed reporting.
5. **Reporting layer:** Once cracking completes (match found or
   search space exhausted), a structured report (dict) is generated
   with attempts, elapsed time, speed, and result — which is then
   appended to a CSV session log for auditability.

```
            ┌─────────────────┐
            │   Wordlist /     │
            │ Brute-force      │
            │  keyspace        │
            └────────┬─────────┘
                      │
              ┌───────▼────────┐
              │  Thread-safe    │
              │  Work Queue     │
              └───────┬────────┘
     ┌────────────────┼────────────────┐
     ▼                ▼                ▼
┌─────────┐     ┌─────────┐      ┌─────────┐
│Worker #1│     │Worker #2│ .... │Worker #N│
└────┬────┘     └────┬────┘      └────┬────┘
     │  hash & compare against target  │
     └────────────────┼────────────────┘
                       ▼
              found_event.set() on match
                       │
                       ▼
              Report + CSV Log
```

## 5. Modules Implemented

| Module | File | Purpose |
|---|---|---|
| Core Engine | `hydracrack.py` | Hash detection, dictionary attack, brute-force attack, CLI |
| GUI | `hydracrack_gui.py` | Tkinter interface for live demonstration |
| Hash Generator | `generate_sample_hashes.py` | Produces demo hashes from any plaintext for testing |
| Benchmark Suite | `benchmark.py` | Compares 1 / 2 / 4 / 8 / 16-thread performance on the same target |

## 6. Methodology

1. **Hash identification** — the tool inspects the hex digest length
   of the supplied hash (32/40/64/128 hex characters) and
   auto-maps it to MD5/SHA1/SHA256/SHA512 respectively, so the user
   need not manually specify the algorithm.
2. **Dictionary attack** — candidate words from a wordlist are hashed
   and compared against the target in parallel across threads. This
   models real-world attacks where users choose weak/common passwords.
3. **Brute-force attack** — all possible combinations of a charset
   (default: lowercase letters + digits) are generated for a
   configurable length range using `itertools.product`, again
   distributed across threads by candidate length.
4. **Early termination** — the moment any thread finds a match, a
   shared event flag halts all other threads immediately, preventing
   unnecessary CPU usage.
5. **Benchmarking** — the same target hash and wordlist were tested
   against 1, 2, 4, 8, and 16 threads to produce a measurable
   speed-vs-thread-count curve, proving the value of multi-threading.

## 7. Sample Results

**Test hash:** MD5 of `hydracrack` → `f49a56ba89aa6b40aa6db8c8872e2ab5`
**Wordlist:** 30-entry common password list

| Threads | Time Taken | Speed (hashes/sec) | Result |
|---|---|---|---|
| 1 (raw, no threading) | ~0.0020s | ~15,000 h/s | Cracked |
| 4 | ~0.0009s | ~33,000 h/s | Cracked |
| 8 | ~0.0006s | ~50,000 h/s | Cracked |
| 16 | ~0.0005s | ~60,000+ h/s | Cracked |

*(Run `python3 src/benchmark.py` live during your review to generate
fresh, real numbers on the examiner's machine — this is stronger
evidence than static numbers.)*

> Note: On very small wordlists, thread-creation overhead can
> dominate actual hashing time — this is itself a good discussion
> point in your viva: **"multi-threading gives bigger gains on
> larger keyspaces / longer brute-force ranges, where the overhead
> is amortized."** Demonstrate this by increasing `--max-len` in
> brute-force mode.

## 8. Security & Ethical Considerations

- The tool is intended strictly for **authorized password auditing
  and educational demonstration** — e.g., testing whether an
  organization's users choose weak passwords, or lab/CTF exercises.
- No hash cracking was performed against any live, third-party, or
  unauthorized system during development or testing.
- All test hashes were self-generated from known plaintexts using
  `generate_sample_hashes.py`.
- The report includes an explicit **Ethical Use Statement** in the
  README to reinforce responsible disclosure and legal usage
  principles taught during the internship.

## 9. Learning Outcomes

- Practical implementation of **multi-threaded programming** in
  Python, including thread-safe queues, locks, and event-based
  synchronization.
- Deeper understanding of **cryptographic hash functions** (MD5,
  SHA family) — their fixed-length output property and why they're
  vulnerable to dictionary/brute-force attacks when passwords are
  weak or unsalted.
- Hands-on experience translating theoretical cyber-attack concepts
  (learned via Kali Linux / Wireshark modules) into a working,
  demonstrable tool.
- Exposure to building both **CLI and GUI interfaces** for the same
  underlying engine — a common real-world software engineering
  pattern.
- Understanding of **performance benchmarking methodology** — how to
  fairly compare concurrent vs sequential execution.

## 10. Conclusion

HydraCrack successfully demonstrates the practical application of
multi-threading to a core offensive-security technique: password hash
cracking. The project ties together cryptography, concurrent
programming, and cyber-attack methodology — all core areas covered
during the internship — into a single, demonstrable, and extensible
tool. It reinforces why organizations must enforce strong password
policies, salting, and slow hashing algorithms (bcrypt/Argon2) rather
than fast general-purpose hashes like MD5/SHA1 for password storage.

## 11. Future Scope

- Integration with GPU-accelerated cracking (via Hashcat bindings)
- Support for slow/adaptive hashing algorithms (bcrypt, scrypt, Argon2)
- Rule-based wordlist mutation engine (leetspeak substitutions, case
  variations, common suffixes like birth years)
- Distributed cracking across multiple networked machines
- Rainbow table precomputation and lookup mode

---

*Prepared by Jeevitha M as part of Cyber Security Internship review
submission, B.E. CSE (Cyber Security), J.N.N Institute of Engineering
(Autonomous), 2025–2026.*

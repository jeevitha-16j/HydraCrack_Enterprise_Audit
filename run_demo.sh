#!/bin/bash
# HydraCrack quick demo script
# Run this during your review to show a full working crack live.

cd "$(dirname "$0")/src"

echo "=== Step 1: Generating a sample hash for 'hydracrack' ==="
python3 generate_sample_hashes.py hydracrack
echo ""

echo "=== Step 2: Copy the MD5 value above, then running dictionary attack ==="
echo "(Edit this script's HASH variable, or run manually)"
read -p "Paste the MD5 hash here: " HASH

python3 hydracrack.py -H "$HASH" -w ../wordlists/common_passwords.txt -t 8

echo ""
echo "=== Step 3: Running benchmark (1 vs multi-threaded speed) ==="
python3 benchmark.py

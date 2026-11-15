#!/usr/bin/env python3
"""Builds assets/oui.tsv, the hardware-address makers the network map names devices with, from IEEE's public
registry (https://standards-oui.ieee.org/oui/oui.txt, downloaded by hand: the app never fetches it).
Usage: python3 scripts/make-oui.py oui.txt"""
import re, sys

SUFFIXES = r"(,?\s*(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|s\.a|srl|s\.r\.l|bv|b\.v|nv|oy|ab|as|a/s|pty|plc|kk|k\.k|pte|sdn\.? bhd|technology|technologies|tech|electronics|electronic|international|holdings|group|communications|systems)\.?)+$"

def short(name):
    n = re.sub(r"\s+", " ", name).strip().strip(".,")
    for _ in range(3):
        n = re.sub(SUFFIXES, "", n, flags=re.I).strip().strip(".,")
    n = re.sub(r"\s*\(.*?\)\s*$", "", n).strip()
    return (n or name.strip())[:32]

rows = {}
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = re.match(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$", line)
    if m:
        rows[m.group(1).lower()] = short(m.group(2))
with open("assets/oui.tsv", "w") as out:
    for k in sorted(rows):
        out.write(f"{k}\t{rows[k]}\n")
print(f"{len(rows)} prefixes")

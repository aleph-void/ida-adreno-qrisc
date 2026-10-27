#!/usr/bin/env python3
"""Turn `qrisc-disasm -r` output into one line per 32-bit word with branch targets as byte
addresses: label lines ("fxnN:", "lN:") are removed and every "#label" / "#<word number>" operand
becomes "#0x<4 * word index>" (Ghidra's code space is byte-addressed).
  mesa_raw.py <raw.txt> <out.txt>"""
import re
import sys

lines = open(sys.argv[1]).read().split("\n")
body = [l for l in lines if not l.startswith(";")]
labels, out, pending = {}, [], []
for l in body:
    if not l.strip():
        continue
    m = re.match(r"^([A-Za-z_][A-Za-z_0-9]*):\s*$", l)
    if m:
        pending.append(m.group(1))
        continue
    for p in pending:
        labels[p] = len(out)
    pending = []
    out.append(l)


def sub(m, idx, line):
    t = m.group(1)
    if t in labels:
        return "#0x%x" % (4 * labels[t])
    if re.fullmatch(r"l\d+", t):
        return "#0x%x" % (4 * int(t[1:]))
    if re.fullmatch(r"-?\d+", t):
        # a target outside the image is printed as a number: the word offset for pc-relative
        # branches, the (sign-extended 26-bit) word address for bl/call/jumpa
        n = int(t)
        if re.match(r"^(\([a-z0-9]+\))*(breq|brne|jump|setsecure)\b", line):
            return "#0x%x" % ((4 * (idx + n)) & 0xffffffff)
        return "#0x%x" % (4 * (n & 0x3ffffff))
    return "#" + t


out = [re.sub(r"#([A-Za-z_0-9-]+)", lambda m, i=i, l=l: sub(m, i, l), l) for i, l in enumerate(out)]
open(sys.argv[2], "w").write("\n".join(out) + "\n")

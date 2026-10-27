#!/usr/bin/env python3
"""Decode corpus for the QRisc differential: 32-bit little-endian instruction words.
  gen_corpus.py <out.bin> [random-words] [seed]
Every value of bits 24-31 x every value of bits 0-5 with four fillings of bits 6-23 (zero, ones,
two random) = 65,536 words, every control/SQE register number in the cread/cwrite/sread/
swrite/load/store groups (32,768), then <random-words> random words (default 50000)."""
import random
import struct
import sys

out = sys.argv[1]
nrand = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
words = []
for hi in range(256):
    for lo in range(64):
        for mid in (0, 0x3ffff, rnd.getrandbits(18), rnd.getrandbits(18)):
            words.append((hi << 24) | (mid << 6) | lo)
# control/SQE register accesses: every register number, both access groups (bit 15)
for op in (0x14, 0x15, 0x16, 0x17):
    for b15 in (0, 1):
        for base in range(0x1000):
            words.append((op << 27) | (b15 << 15) | (3 << 21) | (5 << 16) | base)
words += [rnd.getrandbits(32) for _ in range(nrand)]
open(out, "wb").write(struct.pack("<%dI" % len(words), *words))
print("%d words -> %s" % (len(words), out))

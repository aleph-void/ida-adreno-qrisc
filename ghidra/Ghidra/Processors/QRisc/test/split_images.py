#!/usr/bin/env python3
"""Split a QRisc firmware file into its instruction streams: file word 0 is dropped (the CP and
Mesa skip it); each image starts with a version word and a word whose low 16 bits are the packet
jump-table offset (in words, relative to the image); a7xx appends BV (and LPAC) images after the
0x80-entry table, 32-byte aligned, each with its own header and image-relative branch targets.
If the header's offset does not fit, the whole stream is one image.
  split_images.py <file.fw> <out-prefix>   -> <out-prefix>.0, .1, ... (one per image)"""
import struct
import sys

d = open(sys.argv[1], "rb").read()[4:]
w = struct.unpack("<%dI" % (len(d) // 4), d)
base, n = 0, 0
while base + 2 <= len(w):
    jt = w[base + 1] & 0xffff
    end = base + jt + 0x80
    if jt < 2 or end > len(w):
        break
    open("%s.%d" % (sys.argv[2], n), "wb").write(d[4 * base:4 * end])
    print("image %d: words 0x%x-0x%x, jump table at +0x%x" % (n, base, end, jt))
    n += 1
    base = (end + 7) & ~7
if n == 0:  # no usable jump-table offset in the header: one image, the whole stream
    open("%s.0" % sys.argv[2], "wb").write(d)
    print("image 0: words 0x0-0x%x (no jump table found from the header)" % len(w))

#!/usr/bin/env python3
"""Hand-computed p-code cases for EmuCheck.java, with expectations worked out from Mesa's emulator
source (src/freedreno/qrisc/emu.c, MIT) and, where the two differ, Mesa's ISA documentation
(src/freedreno/qrisc/README.rst, MIT): carry for addhi/subhi, cmp's 0x00/0x2b/0x1e, unsigned
min/max, mul8, msb, rot, shifts, $00 reading as zero, delay slots, branches in delay slots,
call/ret, bl/sret, $data popping $rem, (peek), (rep), (xmov), (sds), control-register and memory
round trips with pre-increment.
Each case is assembled once with Mesa's qrisc-asm (`--rebuild <qrisc-asm>`) into
test/emu/cases_<gen>.txt; the first case of each set sits at address 0 behind the firmware version
word (Mesa counts word 0 = version), so its absolute call targets hold; the others are placed at
0x100 * index and use only pc-relative branches. Each set ends with a deliberately wrong
expectation (broken_*) that EmuCheck must report.
  emu_tests.py <outdir>   -> <outdir>/emu_a6xx.bin, tests_a6xx.txt, emu_a7xx.bin, tests_a7xx.txt
  emu_tests.py --rebuild <qrisc-asm>"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VERSION = {"a6xx": "016ee001", "a7xx": "01730001"}

SLOTBR = "breq $01, 0x1, #a\nbreq $01, 0x2, #b\nmov $02, 0x5\nmov $03, 0x1\na:\nmov $04, 0x1\nb:\nnop"
COMMON = [
    ("add_carry_addhi", "add $03, $01, $02\naddhi $04, $00, $00", "r01=ffffffff,r02=1", "r03=0,r04=1,carry=1"),
    ("sub_borrow_subhi", "sub $03, $01, $02\nsubhi $04, $05, $00", "r01=0,r02=1,r05=5",
     "r03=ffffffff,carry=ffffffff,r04=4"),
    ("add_imm", "add $01, $01, 0x10", "r01=5", "r01=15"),
    ("r00_reads_zero", "add $01, $00, 0x1\nor $02, $00, $03\nmov $04, $00", "r00=5,r03=8,r04=9", "r01=1,r02=8,r04=0"),
    ("mov_is_or_r00", "mov $01, $02", "r02=1234", "r01=1234"),
    ("movi_shift", "mov $01, 0xdead << 16", "-", "r01=dead0000"),
    ("cmp_equal", "cmp $03, $01, $02", "r01=5,r02=5", "r03=2b"),
    ("cmp_less", "cmp $03, $01, $02", "r01=4,r02=5", "r03=1e"),
    ("cmp_greater", "cmp $03, $01, $02", "r01=6,r02=5,r03=77", "r03=0"),
    ("mul8", "mul8 $03, $01, $02", "r01=1ff,r02=103", "r03=2fd"),
    ("min_max_unsigned", "min $03, $01, $02\nmax $04, $01, $02", "r01=ffffffff,r02=1", "r03=1,r04=ffffffff"),
    ("msb", "msb $01, $02", "r02=80", "r01=7"),
    ("msb_zero", "msb $01, $02", "r01=55,r02=0", "r01=0"),
    ("rot_imm", "rot $01, $01, 0x1", "r01=80000001", "r01=3"),
    ("shifts_imm", "shl $01, $01, 0x4\nushr $02, $02, 0x4\nishr $03, $03, 0x4", "r01=f,r02=80000000,r03=80000000",
     "r01=f0,r02=8000000,r03=f8000000"),
    ("not_imm", "not $01, 0x5", "-", "r01=fffffffa"),
    ("setbit_clrbit", "setbit $01, $01, b3\nclrbit $02, $02, b0", "r01=0,r02=ff", "r01=8,r02=fe"),
    ("brne_taken_delay_slot", "brne $01, 0x3, #l\nmov $02, 0x1\nmov $03, 0x1\nl:\nnop", "r01=4", "r02=1,r03=0"),
    ("brne_not_taken", "brne $01, 0x3, #l\nmov $02, 0x1\nmov $03, 0x1\nl:\nnop", "r01=3", "r02=1,r03=1"),
    ("breq_bit", "breq $01, b2, #l\nnop\nmov $03, 0x1\nl:\nnop", "r01=4", "r03=0"),
    # a branch in a branch's delay slot (Mesa: the second branch's slot runs, then its target)
    ("slot_branch_second_taken", SLOTBR, "r01=2", "r02=5,r03=0,r04=0"),
    ("slot_branch_first_taken", SLOTBR, "r01=1", "r02=0,r03=0,r04=1"),
    ("slot_branch_none_taken", SLOTBR, "r01=3", "r02=5,r03=1,r04=1"),
    ("slot_jump_jump", "jump #a\njump #a\nmov $02, 0x1\na:\nnop", "-", "r02=0"),
    # Mesa's test-firmware gcd routine: a chain of branches, each in the previous one's slot
    ("gcd_branch_chain", "t:\ncmp $04, $02, $03\nbreq $04, b0, #d\nbrne $04, b1, #m\nbreq $04, b2, #t\n"
     "sub $03, $03, $02\nm:\njump #t\nsub $02, $02, $03\nd:\nnop", "r02=c,r03=12", "r02=6,r03=6"),
    ("rep_add", "(rep)add $01, $01, 0x1", "r01=10,rem=3", "r01=13,rem=0"),
    # (xmovN): to a plain register the extra moves are discarded; to $addr they write $data
    ("xmov1_discarded", "(xmov1)add $01, $02, $03", "r02=1,r03=2,rem=2,data=77", "r01=3,rem=1,data=77"),
    ("xmov2_addr", "(xmov2)mov $addr, $02", "r02=9,rem=5", "addr=9,data=9,rem=3"),
    # reading $data pops a packet word: $rem counts down, once per pass also under (rep)
    ("data_pop_rem", "add $01, $data, 0x1", "data=7,rem=3", "r01=8,rem=2"),
    ("rep_data", "(rep)add $01, $01, $data", "r01=0,data=2,rem=3", "r01=6,rem=0"),
    ("cwrite_cread", "cwrite $01, [$00 + 0x50]\ncread $02, [$00 + 0x50]", "r01=cafe", "r02=cafe"),
    ("cwrite_preinc", "cwrite $01, [$03 + 0x4]!", "r01=1,r03=10", "r03=14"),
    ("store_load", "store $01, [$02 + 0x8]\nload $03, [$02 + 0x8]", "r01=beef,r02=1000", "r03=beef"),
]
CASES = {
    "a6xx": [("call_ret", "call #f\nnop\nmov $01, 0x9\njump #e\nnop\nf:\nmov $02, 0x7\nret\nnop\ne:\nnop", "-",
              "r02=7,r01=9")] + COMMON,
    "a7xx": [("bl_sret", "bl #f\nnop\nmov $01, 0x9\njump #e\nnop\nf:\nmov $02, 0x7\nsret\nnop\ne:\nnop", "-",
              "r02=7,r01=9,lr=3")] + COMMON + [
        ("ubfx", "ubfx $01, $02, b4, b7", "r02=abcd", "r01=c"),
        ("bfi", "bfi $01, $02, b8, b11", "r01=1,r02=5", "r01=501"),
        ("bic", "bic $01, $01, $02", "r01=ff,r02=f", "r01=f0"),
        ("setbit_reg", "setbit $01, $01, $02", "r01=0,r02=b", "r01=20"),
        ("peek_keeps_rem", "(peek)add $01, $02, $data", "r02=1,data=5,rem=3", "r01=6,rem=3"),
        ("rep_sds2_three_words", "(rep)(sds2)cwrite $data, [$00 + 0x10]", "data=5,rem=6", "rem=0"),
    ],
}
CASES["a6xx"].append(("broken_add_imm", "add $01, $01, 0x10", "r01=5", "r01=16"))
CASES["a7xx"].append(("broken_add_imm", "add $01, $01, 0x10", "r01=5", "r01=16"))


def assemble(qasm, gen, asm):
    with tempfile.TemporaryDirectory() as t:
        open(t + "/c.asm", "w").write("[%s]\n%s\n" % (VERSION[gen], asm))
        subprocess.run([qasm, t + "/c.asm", t + "/c.fw"], check=True, capture_output=True)
        d = open(t + "/c.fw", "rb").read()
    return d[4:]   # drop file word 0; keep the version word (Mesa's instruction index 0)


if sys.argv[1] == "--rebuild":
    for gen, cases in CASES.items():
        rows = ["%s %s" % (n, assemble(sys.argv[2], gen, a).hex()) for n, a, _, _ in cases]
        open(os.path.join(HERE, "emu", "cases_%s.txt" % gen), "w").write("\n".join(rows) + "\n")
    sys.exit(0)
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for gen, cases in CASES.items():
    code = dict(l.split() for l in open(os.path.join(HERE, "emu", "cases_%s.txt" % gen)))
    img = bytearray(0x100 * (len(cases) + 2))
    with open(os.path.join(out, "tests_%s.txt" % gen), "w") as f:
        for i, (name, _, init, exp) in enumerate(cases):
            b = bytes.fromhex(code[name])
            base = 0 if i == 0 else 0x100 * i
            img[base:base + len(b)] = b
            # start after the version word; stop after the last instruction
            f.write("%s %x %x %s %s\n" % (name, base + 4, base + len(b), init, exp))
    open(os.path.join(out, "emu_%s.bin" % gen), "wb").write(img)
print(", ".join("%d cases (%s)" % (len(c), g) for g, c in CASES.items()))

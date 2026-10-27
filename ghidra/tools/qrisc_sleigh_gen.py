#!/usr/bin/env python3
"""Generate the Ghidra SLEIGH module for QRisc (Adreno afuc) from common/qrisc_isa_tables.py.

Emits, under ghidra/Ghidra/Processors/QRisc/data/languages/:
  qrisc.sinc            core: spaces, registers, token, operand sub-tables, macros
  qrisc_gen6.sinc       a6xx instruction constructors
  qrisc_gen7.sinc       a7xx instruction constructors (a7xx_gen3 and a8xx reuse them)
  qrisc_creg_<dom>.sinc control/SQE register names for one register domain

  ../ghidra_scripts/QRiscFirmwareHelper.java: the PM4 packet-name tables (between markers)
  qrisc_<lang>.pspec    processor spec per language: volatile FIFO pseudo-registers and CREG/SREG
                        spaces, control/SQE register names as symbols, the bootstrap entry

The .slaspec / .ldefs / .cspec are hand-written and @include these.

Display follows Mesa's qrisc-disasm (isaspec display strings of qrisc.xml, the control and SQE
register names of the Mesa register database) except that SLEIGH identifiers cannot contain `$`:
registers are r00..r19, sp, lr, rem, memdata, regdata, data, addr, usraddr.

Semantics follow Mesa's emulator (src/freedreno/qrisc/emu.c, MIT): the ALU operations including
the carry used by addhi/subhi, cmp's 0x00/0x2b/0x1e result, mul8, min/max (unsigned), msb, rot,
setbit, ubfx/bfi, the (rep) repeat on $rem, the (xmov) extra moves, pre-increment, the 64-bit
load/store address from LOAD_STORE_HI, control/SQE register accesses as memory in the CREG and SREG
spaces, delay slots, call/ret through a return stack, bl/sret through $lr.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "common"))
import qrisc_isa_tables as T  # noqa: E402

LANGDIR = os.path.join(REPO, "ghidra", "Ghidra", "Processors", "QRisc", "data", "languages")

GPRS = ["r%02x" % i for i in range(0x1a)] + ["sp", "lr"]
SRC_REGS = GPRS + ["rem", "memdata", "regdata", "data"]
DST_REGS = GPRS + ["rem", "addr", "usraddr", "data"]
SPECIAL_REGS = ["rem", "data", "memdata", "regdata", "addr", "usraddr"]

OPFIELDS = set()


def runs(mask):
    out, i = [], 0
    while i < 32:
        if mask & (1 << i):
            j = i
            while j < 32 and mask & (1 << j):
                j += 1
            out.append((i, j - 1))
            i = j
        else:
            i += 1
    return out


def opcode_constraint(rec):
    parts = []
    for (lo, hi) in runs(rec["mask"]):
        OPFIELDS.add((lo, hi))
        parts.append("op%d_%d=0x%x" % (lo, hi, (rec["match"] >> lo) & ((1 << (hi - lo + 1)) - 1)))
    return parts


def field(rec, name):
    for f in rec["fields"]:
        if f["name"] == name:
            return f
    return None


def imm_name(rec, name):
    f = field(rec, name)
    return "imm_%d_%d" % (f["low"], f["high"])


IMMS = {(0, 15), (0, 11)}

# ALU semantics (a = first source, b = second source or immediate, d = destination)
ALU = {
    "add": "local r:4 = {a} + {b};\n  carry = zext(carry({a}, {b}));\n  {d} = r;",
    "addhi": "{d} = {a} + {b} + carry;",
    "sub": "local r:4 = {a} - {b};\n  carry = 0 - zext({a} < {b});\n  {d} = r;",
    "subhi": "{d} = {a} - {b} + carry;",
    "and": "{d} = {a} & {b};",
    "or": "{d} = {a} | {b};",
    "xor": "{d} = {a} ^ {b};",
    "bic": "{d} = {a} & ~{b};",
    "shl": "{d} = {a} << ({b} & 31);",
    "ushr": "{d} = {a} >> ({b} & 31);",
    "ishr": "{d} = {a} s>> ({b} & 31);",
    "rot": "rotl({d}, {a}, {b});",
    "mul8": "{d} = ({a} & 0xff) * ({b} & 0xff);",
    "min": "minu({d}, {a}, {b});",
    "max": "maxu({d}, {a}, {b});",
    "cmp": "cmp3({d}, {a}, {b});",
    "setbit": "setbitv({d}, {a}, {b});",
}


def C(display, pattern, sem):
    return ":%s is %s {\n  %s\n}\n" % (display, " & ".join(p for p in pattern if p), sem)


def rep_wrap(sem, ops=()):
    """(rep): repeat while $rem != 0 (reppre/reppost); the source operands are built after the
    $rem check, as reading $data counts $rem down."""
    builds = "".join("build %s;\n  " % o for o in ops if o in ("s21", "s16", "s16k"))
    return ("build reppre;\n  " + builds + sem + "\n  build reppost;")


def emit_insn(rec):
    name, mn, d = rec["name"], rec["mnemonic"], rec["display"] or ""
    cons = opcode_constraint(rec)
    out = []
    has = lambda f: field(rec, f) is not None  # noqa: E731
    pre = ""
    pat_pre = []
    if has("REP"):
        pre += "^rep"
        pat_pre += ["rep", "reppre", "reppost"]
    if has("XMOV"):
        pre += "^xmov"
        pat_pre += ["xmov", "xmovsem"]
    if has("PEEK"):
        pre += "^peek"
        pat_pre.append("peek")
    if name == "movi":
        mn = "mov"
    disp_mn = (":" + pre + '^"%s"' % mn) if pre else (":" + mn)

    def cons_line(disp_tail, extra, sem, mnem=None):
        dm = disp_mn if mnem is None else ((":" + pre[1:] + '^"%s"' % mnem) if pre else (":" + mnem))
        body = sem
        if has("REP"):
            body = rep_wrap(sem)
        return C(dm[1:] + ((" " + disp_tail) if disp_tail else ""),
                 cons + pat_pre + extra, body).replace(":", ":", 1)

    def emit(disp_tail, extra, sem, mnem=None):
        dm = disp_mn if mnem is None else ((":" + pre + '^"%s"' % mnem) if pre else (":" + mnem))
        if has("PEEK"):
            disp_tail, sem = re.sub(r"\bs16\b", "s16k", disp_tail), re.sub(r"\bs16\b", "s16k", sem)
            extra = ["s16k" if x == "s16" else x for x in extra]
        body = rep_wrap(sem, extra) if has("REP") else sem
        out.append(":%s%s is %s {\n  %s\n}\n" % (dm[1:], (" " + disp_tail) if disp_tail else "",
                                                 " & ".join(cons + pat_pre + extra), body))

    xm = ("\n  build xmovsem;" if has("XMOV") else "")
    if "{SRC2}" in d:  # ALU, two register sources
        sem = ALU[mn].format(d="d11", a="s21", b="s16") + xm
        emit("d11, s21, s16", ["d11", "s21", "s16"], sem)
        if name == "or":  # override: SRC1 == 0 -> mov
            emit("d11, s16", ["d11", "rs21=0", "s16"], "d11 = s16;" + xm, mnem="mov")
    elif name in ("msb", "not") and "{SRC1}" in d and "RIMMED" not in str(rec["fields"]):
        sem = ("msb(d11, s16);" if mn == "msb" else "d11 = ~s16;") + xm
        emit("d11, s16", ["d11", "s16"], sem)
    elif name == "noti":
        emit("d16, " + imm_name(rec, "IMMED"), ["d16", imm_name(rec, "IMMED")],
             "local i:4 = %s;\n  d16 = ~i;" % imm_name(rec, "IMMED"))
    elif name == "movi":
        im = imm_name(rec, "RIMMED")
        emit("d16, %s << sh5" % im, ["d16", im, "sh5"],
             "local i:4 = %s;\n  local s:4 = sh5;\n  d16 = i << s;" % im)
        emit("d16, %s" % im, ["d16", im, "sh5=0"], "local i:4 = %s;\n  d16 = i;" % im)
    elif "{RIMMED}" in d:  # ALU with an immediate
        im = imm_name(rec, "RIMMED")
        IMMS.add((field(rec, "RIMMED")["low"], field(rec, "RIMMED")["high"]))
        sem = "local i:4 = %s;\n  " % im + ALU[mn].format(d="d16", a="s21", b="i")
        emit("d16, s21, %s" % im, ["d16", "s21", im], sem)
    elif name in ("setbiti", "clrbit"):
        op = "|" if mn == "setbit" else "& ~"
        emit("d16, s21, \"b\"^bit_1_5", ["d16", "s21", "bit_1_5"],
             "local b:4 = bit_1_5;\n  d16 = s21 %s (1:4 << b);" % op)
    elif name in ("ubfx", "bfi"):
        emit('d16, s21, "b"^blo, "b"^bhi', ["d16", "s21", "blo", "bhi"],
             "local lo:4 = blo;\n  local hi:4 = bhi;\n  %s(d16, s21, lo, hi);" % name)
    elif name in ("cread", "sread"):
        tbl = "cbase" if name == "cread" else "sbase"
        sp = "CREG" if name == "cread" else "SREG"
        emit("d16, [s21 + %s]preinc" % tbl, ["d16", "s21", tbl, "preinc", "preincv", "rs21"],
             "local a:4 = s21 + %s;\n  local pi:1 = preincv;\n  if (pi == 0) goto <rd>;\n  rs21 = a;\n<rd>\n"
             "  d16 = *[%s]:4 (a * 4);" % (tbl, sp))
    elif name in ("cwrite", "swrite"):
        tbl = "cbase" if name == "cwrite" else "sbase"
        sp = "CREG" if name == "cwrite" else "SREG"
        sds = "^sds" if has("SDS") else ""
        disp = (pre + sds)[1:] if (pre + sds) else ""
        pat = cons + pat_pre + (["sds", "sdsx"] if has("SDS") else []) + ["s16", "s21", tbl, "preinc", "preincv", "rs21"]
        sem = ("local v:4 = s16;\n  local a:4 = s21 + %s;\n  local pi:1 = preincv;\n  if (pi == 0) goto <wr>;\n  rs21 = a;\n<wr>\n"
               "  *[%s]:4 (a * 4) = v;" % (tbl, sp)) + ("\n  build sdsx;" if has("SDS") else "")
        body = rep_wrap(sem, ["s16", "s21"]) if has("REP") else sem
        out.append(":%s%s s16, [s21 + %s]preinc is %s {\n  %s\n}\n" % (
            "^" + disp + "^" if disp else "", '"%s"' % name if disp else name, tbl, " & ".join(pat), body))
    elif name in ("load", "store"):
        im = imm_name(rec, "IMMED")
        if name == "load":
            emit("d16, [s21 + %s]preinc" % im, ["d16", "s21", im, "preinc", "preincv", "rs21"],
                 "local o:4 = %s;\n  local a:8;\n  lsaddr(a, s21);\n  a = a + zext(o);\n  local pi:1 = preincv;\n  if (pi == 0) goto <ld>;\n"
                 "  rs21 = s21 + o;\n<ld>\n  d16 = *[MEM]:4 a;" % im)
        else:
            emit("s16, [s21 + %s]preinc" % im, ["s16", "s21", im, "preinc", "preincv", "rs21"],
                 "local v:4 = s16;\n  local o:4 = %s;\n  local a:8;\n  lsaddr(a, s21);\n  a = a + zext(o);\n"
                 "  local pi:1 = preincv;\n  if (pi == 0) goto <st>;\n  rs21 = s21 + o;\n<st>\n  *[MEM]:4 a = v;" % im)
    elif name in ("breqi", "brnei"):
        c = "==" if mn == "breq" else "!="
        emit('s21, imm5, "#"^rel', ["s21", "imm5", "rel"],
             "local t:1 = s21 %s imm5;\n  delayslot(1);\n  if (t) goto rel;" % c)
    elif name in ("breqb", "brneb"):
        c = "!= 0" if mn == "breq" else "== 0"
        if name == "brneb":
            out.append(':jump "#"^rel is %s & bit5b=0 & rs21=0 & rel {\n  delayslot(1);\n  goto rel;\n}\n'
                       % " & ".join(cons))
        emit('s21, "b"^bit5b, "#"^rel', ["s21", "bit5b", "rel"],
             "local t:1 = ((s21 >> bit5b) & 1) %s;\n  delayslot(1);\n  if (t) goto rel;" % c)
    elif name == "call":
        out.append(':call "#"^abs is %s & abs {\n  local ra:4 = inst_start + 8;\n  csp = csp - 4;\n'
                   '  *[hwstack]:4 csp = ra;\n  delayslot(1);\n  call abs;\n}\n' % " & ".join(cons))
    elif name == "bl":
        out.append(':bl "#"^abs is %s & abs {\n  lr = (inst_start >> 2) + 2;\n  delayslot(1);\n'
                   '  call abs;\n}\n' % " & ".join(cons))
    elif name == "jumpa":
        out.append(':jumpa "#"^abs is %s & abs {\n  delayslot(1);\n  goto abs;\n}\n' % " & ".join(cons))
    elif name in ("ret", "iret"):
        out.append(':%s is %s {\n  local ra:4 = *[hwstack]:4 csp;\n  csp = csp + 4;\n  delayslot(1);\n'
                   '  return [ra];\n}\n' % (name, " & ".join(cons)))
    elif name == "sret":
        out.append(':sret is %s {\n  local t:4 = lr << 2;\n  delayslot(1);\n  return [t];\n}\n'
                   % " & ".join(cons))
    elif name == "jumpr":
        out.append('s0: rs0 is rs0 { export rs0; }\ns0: "r00" is rs0=0 { export 0:4; }\n'
                   's0: "data" is rs0=0x1f { local v:4 = data; rem = rem - 1; popped = 1; export v; }\n')
        out.append(':jump s0 is %s & s0 {\n  local t:4 = s0 << 2;\n  delayslot(1);\n  goto [t];\n}\n'
                   % " & ".join(cons))
    elif name == "waitin":
        out.append(':waitin is %s {\n  delayslot(1);\n  local h:4 = qrisc_waitin();\n  goto [h];\n}\n'
                   % " & ".join(cons))
    elif name == "setsecure":
        # Mesa: the target is always pc + 3 words ("skips the next two instructions if successful")
        out.append(':setsecure "r02", "#"^skip3 is %s & skip3 {\n  local ok:1 = qrisc_setsecure(r02);\n'
                   '  if (ok) goto skip3;\n}\n' % " & ".join(cons))
    elif name == "nop":
        emit("", [], "")
    else:
        raise SystemExit("unhandled instruction %s %r" % (name, d))
    return "".join(out)


def emit_regnames(dom, prefix, table):
    L = ["# %s names (Mesa register database, as qrisc-disasm prints them)" % dom]
    if table == "cbase":
        hi = [o for (o, n, nm) in T.REG_DOMAINS[dom] if nm == "LOAD_STORE_HI"][0]
        L.append("# load/store address: LOAD_STORE_HI (control register 0x%x) supplies bits 63..32" % hi)
        L.append("macro lsaddr(a, r) { a = (zext(*[CREG]:4 (0x%x:4 * 4)) << 32) | zext(r); }" % hi)
    seen = set()
    for (off, n, nm) in T.REG_DOMAINS[dom]:
        for i in range(n):
            if off + i in seen:
                continue
            seen.add(off + i)
            label = "%s%s%s" % (prefix, nm, "" if i == 0 else "+0x%x" % i)
            L.append('%s: "%s" is preinc=0 & base12=0x%x { local t:4 = 0x%x; export t; }'
                     % (table, label, off + i, off + i))
    return "\n".join(L) + "\n"


def emit_pspec(dom):
    L = ['<?xml version="1.0" encoding="UTF-8"?>', "<!-- AUTO-GENERATED by ghidra/tools/qrisc_sleigh_gen.py; do not edit. -->",
         "<processor_spec>", '  <programcounter register="pc"/>',
         "  <!-- the FIFO/queue pseudo-registers (rem data memdata regdata addr usraddr) and the control",
         "       and SQE registers have side effects: every access is kept -->",
         '  <volatile outputop="write_volatile" inputop="read_volatile">',
         '    <range space="register" first="0x80" last="0x97"/>',
         '    <range space="CREG" first="0x0" last="0xffffffff"/>',
         '    <range space="SREG" first="0x0" last="0xffffffff"/>',
         "  </volatile>",
         "  <!-- 12-bit register numbers, byte-addressed (number * 4) -->",
         "  <default_memory_blocks>",
         '    <memory_block name="CREG" start_address="CREG:0x0" length="0x4000" mode="rwv" initialized="false"/>',
         '    <memory_block name="SREG" start_address="SREG:0x0" length="0x4000" mode="rwv" initialized="false"/>',
         "  </default_memory_blocks>", "  <default_symbols>",
         "    <!-- instruction stream with file word 0 stripped: version word, jump-table offset word,",
         "         then the bootstrap routine -->",
         '    <symbol name="bootstrap" address="code:0x8" entry="true"/>']
    for (d, space) in ((dom, "CREG"), (T.SQE_DOMAIN, "SREG")):
        seen = set()
        for (off, n, nm) in T.REG_DOMAINS[d]:
            for i in range(n):
                if off + i in seen:
                    continue
                seen.add(off + i)
                L.append('    <symbol name="%s%s" address="%s:0x%x"/>' % (nm, "" if i == 0 else "_%d" % i, space, 4 * (off + i)))
    L += ["  </default_symbols>", "</processor_spec>", ""]
    return "\n".join(L)


def emit_pm4_names(java):
    """Fill the PM4 packet-name tables (index -> CP_* name per generation) of the import helper."""
    begin, end = "    // BEGIN GENERATED PM4 NAMES", "    // END GENERATED PM4 NAMES"
    head, rest = java.split(begin, 1)
    tail = rest.split(end, 1)[1]
    L = [begin + rest.split("\n", 1)[0]]
    for gen in (6, 7, 8):
        names = [None] * 0x80
        for (i, nm, lo, hi) in T.PM4_PACKETS:
            if lo <= gen <= hi and i < 0x80:
                names[i] = nm
        L.append("    static final String[] PM4_GEN%d = {" % gen)
        for k in range(0, 0x80, 4):
            L.append("        " + " ".join(('"%s",' % n) if n else "null," for n in names[k:k + 4]))
        L.append("    };")
    return head + "\n".join(L) + "\n" + end + tail


def emit_core():
    L = []
    A = L.append
    A("# AUTO-GENERATED core SLEIGH for QRisc (afuc). Source: Mesa %s" % T.PINNED_COMMIT)
    A("# Generated by ghidra/tools/qrisc_sleigh_gen.py -- do not edit by hand.\n")
    A("define endian=little;")
    A("define alignment=4;\n")
    A("define space code     type=ram_space      size=4 default;")
    A("define space register type=register_space size=4;")
    A("# control and SQE registers, one 32-bit cell per register at index * 4")
    A("define space CREG     type=ram_space      size=4;")
    A("define space SREG     type=ram_space      size=4;")
    A("# GPU memory reached by load/store (64-bit addresses: LOAD_STORE_HI:reg)")
    A("define space MEM      type=ram_space      size=8;")
    A("# call/ret return stack")
    A("define space hwstack  type=ram_space      size=4;\n")
    A("define register offset=0x00 size=4 [ %s ];" % " ".join(GPRS))
    A("define register offset=0x80 size=4 [ %s ];" % " ".join(SPECIAL_REGS))
    A("define register offset=0x100 size=4 [ pc csp carry ];")
    A("# pending branch of a branch that sits in another branch's delay slot (see pendpost)")
    A("define register offset=0x110 size=1 [ pflag ];")
    A("# set when an instruction pops $data, so (rep) does not decrement $rem a second time")
    A("define register offset=0x111 size=1 [ popped ];")
    A("# words read and thrown away ((sdsN) extra reads)")
    A("define register offset=0x114 size=4 [ sink ];")
    A("define register offset=0x200 size=4 [ contextreg ];")
    A("define context contextreg")
    A("  inslot = (0,0) noflow   # this instruction is in a delay slot")
    A("  pend   = (1,1) noflow   # the previous instruction was a branch in a delay slot")
    A("  ptgt   = (2,31) noflow  # ... and this is its target (word address)")
    A(";\n")
    return "\n".join(L)


def emit_token():
    L = ["define token instr(32)"]
    fields = [("rep", 26, 26), ("peek", 8, 8), ("xmov", 9, 10), ("sds", 12, 13), ("preinc", 14, 14), ("preincv", 14, 14),
              ("d11", 11, 15), ("d16", 16, 20), ("rs21", 21, 25), ("rs16", 16, 20), ("rs0", 0, 4),
              ("sh5", 21, 25), ("imm5", 16, 20), ("boff", 0, 15), ("bit_1_5", 1, 5), ("bit5b", 16, 20),
              ("blo", 0, 4), ("bhi", 5, 9), ("base12", 0, 11), ("t26", 0, 25)]
    for (nm, lo, hi) in fields:
        L.append("  %-8s = (%d,%d)%s" % (nm, lo, hi, " signed" if nm == "boff" else ""))
    for (lo, hi) in sorted(IMMS):
        L.append("  imm_%d_%d = (%d,%d)" % (lo, hi, lo, hi))
    for (lo, hi) in sorted(OPFIELDS):
        L.append("  op%d_%d = (%d,%d)" % (lo, hi, lo, hi))
    L.append(";\n")
    L.append("attach variables [ rs21 rs16 rs0 ] [ %s ];" % " ".join(SRC_REGS))
    L.append("attach variables [ d11 d16 ] [ %s ];" % " ".join(DST_REGS))
    L.append('attach names [ preinc ] [ "" "!" ];')
    L.append('attach names [ rep ] [ "" "(rep)" ];')
    L.append('attach names [ peek ] [ "" "(peek)" ];')
    L.append('attach names [ xmov ] [ "" "(xmov1)" "(xmov2)" "(xmov3)" ];')
    L.append('attach names [ sds ] [ "" "(sds1)" "(sds2)" "(sds3)" ];\n')
    L.append("define pcodeop qrisc_waitin;     # wait for the next packet; returns its handler")
    L.append("define pcodeop qrisc_setsecure;  # secure-mode switch (conditional skip; undocumented)")
    L.append("")
    L.append("# source operands: $00 reads as zero (Mesa emu_get_gpr_reg_alu); writes to it are kept.")
    L.append("# Reading $data pops the next packet word and decrements $rem (Mesa qrisc README, \"Reading")
    L.append("# Memory and Registers\"); with (peek) (s16k) it does neither. x16 reads without the")
    L.append("# decrement, for the (xmov)/(sds) extra reads, which count $rem themselves.")
    L.append("# $memdata and $regdata are the memory/register read queues: volatile reads.")
    for f in ("s21", "rs21"), ("s16", "rs16"):
        L.append("%s: %s is %s { export %s; }" % (f[0], f[1], f[1], f[1]))
        L.append("%s: \"r00\" is %s=0 { export 0:4; }" % (f[0], f[1]))
        L.append("%s: \"data\" is %s=0x1f { local v:4 = data; rem = rem - 1; popped = 1; export v; }" % (f[0], f[1]))
    L.append("s16k: s16 is s16 { export s16; }")
    L.append("s16k: \"data\" is rs16=0x1f & peek=1 { local v:4 = data; export v; }")
    L.append("x16: rs16 is rs16 { export rs16; }")
    L.append("x16: \"r00\" is rs16=0 { export 0:4; }")
    L.append('rel: reloc is boff [ reloc = inst_start + boff * 4; ] { export *:4 reloc; }')
    L.append('skip3: reloc is epsilon [ reloc = inst_start + 12; ] { export *:4 reloc; }')
    L.append('abs: reloc is t26 [ reloc = t26 * 4; ] { export *:4 reloc; }')
    L.append("")
    L.append("""# control/SQE register operand: a name from the register database, or the number
cbase: base12 is base12 { local t:4 = base12; export t; }
sbase: base12 is base12 { local t:4 = base12; export t; }

# (rep): the instruction runs while $rem != 0; a pass decrements $rem unless it already did by
# reading $data (Mesa qrisc README, "(rep)")
# Branches in delay slots. The CP has one delay slot and firmware often puts a second branch in
# it (two-way splits such as `brne $03, b0, #a` / `breq $03, b0, #b`, switch chains of breq,
# `jump #x` twice). Mesa's emulator runs that like a pipeline: a branch in a slot sets its own
# target, its slot is the next instruction, and when both branches are taken the instruction at
# the first target runs before the second target. Ghidra rejects nested delay slots, so a branch
# decoded in a slot (inslot) has no delay slot of its own: it records its condition in pflag and
# hands its target to the next instruction by context; that instruction (pend) runs, then takes
# the branch if pflag is set (pendpost). A delayed branch that is taken clears pflag, so the case
# "both taken" ends at the first target (in firmware the two conditions are exclusive).
ptarget: reloc is ptgt [ reloc = ptgt << 2; ] { export *:4 reloc; }
pendpost: is pend=0 { }
pendpost: is pend=1 & ptarget { local f:1 = pflag; pflag = 0; if (f) goto ptarget; }

reppre:  is rep=0 { }
reppre:  is rep=1 & pendpost { if (rem != 0) goto <go>; build pendpost; goto inst_next; <go> popped = 0; }
reppost: is rep=0 & pendpost { build pendpost; }
reppost: is rep=1 { if (popped != 0) goto <p>; rem = rem - 1; <p> goto inst_start; }

# (xmovN): after the ALU result, M = min(N, $rem) extra moves of the second source, each
# decrementing $rem: `mov $data, src2` (M = 1, 2) or data, dst, data (M = 3). Unless the
# destination is $addr, $usraddr or $data, $data in those moves is replaced by $00, i.e. the
# moves are discarded (Mesa qrisc README, "eXtra Moves")
xmovsem: is xmov=0 { }
xmovsem: is xmov=1 & d11>=0x1d & x16 {
  if (rem == 0) goto <x>;
  rem = rem - 1; data = x16;
<x>
}
xmovsem: is xmov=1 & x16 {
  if (rem == 0) goto <x>;
  rem = rem - 1; r00 = x16;
<x>
}
xmovsem: is xmov=2 & d11>=0x1d & x16 {
  if (rem == 0) goto <x>;
  rem = rem - 1; data = x16;
  if (rem == 0) goto <x>;
  rem = rem - 1; data = x16;
<x>
}
xmovsem: is xmov=2 & x16 {
  if (rem == 0) goto <x>;
  rem = rem - 1; r00 = x16;
  if (rem == 0) goto <x>;
  rem = rem - 1; r00 = x16;
<x>
}
xmovsem: is xmov=3 & d11>=0x1d & d11 & x16 {
  if (rem == 0) goto <x>;
  rem = rem - 1; data = x16;
  if (rem == 0) goto <x>;
  rem = rem - 1; d11 = x16;
  if (rem == 0) goto <x>;
  rem = rem - 1; data = x16;
<x>
}
xmovsem: is xmov=3 & d11 & x16 {
  if (rem == 0) goto <x>;
  rem = rem - 1; r00 = x16;
  if (rem == 0) goto <x>;
  rem = rem - 1; d11 = x16;
  if (rem == 0) goto <x>;
  rem = rem - 1; r00 = x16;
<x>
}

# (sdsN) on cwrite: the source is read N more times; only for @DRAW_STATE_SET_HDR do the words
# go anywhere (the draw-state RAM, internal to the CP) (Mesa qrisc README, "Set Draw State")
sdsx: is sds=0 { }
sdsx: is sds=1 & x16 { sink = x16; }
sdsx: is sds=2 & x16 { sink = x16; sink = x16; }
sdsx: is sds=3 & x16 { sink = x16; sink = x16; sink = x16; }
sdsx: is sds=1 & rs16=0x1f { sink = data; rem = rem - 1; popped = 1; }
sdsx: is sds=2 & rs16=0x1f { sink = data; sink = data; rem = rem - 2; popped = 1; }
sdsx: is sds=3 & rs16=0x1f { sink = data; sink = data; sink = data; rem = rem - 3; popped = 1; }

macro rotl(d, a, b) {
  local n:4 = b;
  local m:4 = (n ^ (0 - zext(n s< 0))) + zext(n s< 0);   # |n| (negative: rotate by -n, Mesa)
  m = m & 31;
  d = (a << m) | (a >> ((32 - m) & 31));
}
macro minu(d, a, b) { d = a + zext(b < a) * (b - a); }
macro maxu(d, a, b) { d = a + zext(b > a) * (b - a); }
# cmp: 0x00 if a > b, 0x2b if equal, 0x1e if a < b (unsigned)
macro cmp3(d, a, b) { d = zext(a == b) * 0x2b + zext(a < b) * 0x1e; }
macro msb(d, a) { d = zext(a != 0) * (31 - lzcount(a)); }
# setbit (register form): bit = b >> 1, value = b & 1
macro setbitv(d, a, b) {
  local bit:4 = (b >> 1) & 31;
  local v:4 = b & 1;
  d = (a & ~(1 << bit)) | (v << bit);
}
# mask of n low bits (n >= 32: all ones)
macro ubfx(d, s, lo, hi) {
  local n:4 = hi - lo + 1;
  local m:4 = (zext(n < 32) * ((1 << (n & 31)) - 1)) | (zext(n >= 32) * 0xffffffff);
  d = (s >> lo) & m;
}
macro bfi(d, s, lo, hi) {
  local n:4 = hi - lo + 1;
  local m:4 = (zext(n < 32) * ((1 << (n & 31)) - 1)) | (zext(n >= 32) * 0xffffffff);
  d = d | ((s & m) << lo);
}
""")
    return "\n".join(L)


XFER = re.compile(r"^\s*(delayslot\(1\);|goto [^<]|call |return |if \(\w+\) goto [^<])")


def add_pend(text):
    """Branch-in-delay-slot support (see pendpost in qrisc.sinc): every constructor takes a pending
    branch (pendpost: through reppre/reppost when it has (rep), first when it is delayed, else
    before its own control transfer or at its end), delayed instructions mark their slot (inslot)
    and clear pflag when they are taken, and branches get an in-slot variant without a delay
    slot."""
    out = []
    for blk in re.split(r"(?m)^(?=:)", text):
        if not blk.startswith(":"):
            out.append(blk)
            continue
        m = re.match(r"(:.*? is )(.*?) \{\n(.*?)^\}\n(.*)", blk, re.S | re.M)
        head, pat, body, rest = m.groups()
        lines = body.rstrip("\n").split("\n")
        delayed = any(l.strip() == "delayslot(1);" for l in lines)
        variant = None
        if re.match(r':(breq|brne|jump "#"|jumpa)', head):
            cond = [l for l in lines if l.strip().startswith("local t:1 =")]
            tgt = "t26" if "abs" in pat else "(inst_start >> 2) + boff"
            fld = "t26" if "abs" in pat else "boff"
            # (no pendpost: the instruction before a slot is a delayed one, never a pending branch;
            # and the context assignments here would be seen by this instruction's own operands)
            variant = ("%s%s & inslot=1 & " + fld + " [ pend = 1; ptgt = %s; globalset(inst_next, pend); globalset(inst_next, ptgt); ] {\n%s\n  pflag = %s;\n}\n") % (
                head, pat, tgt, cond[0] if cond else "  local t:1 = 1;", "t")
        if "reppre" not in pat:
            pat += " & pendpost"
            i = 0 if delayed else next((k for k, l in enumerate(lines) if XFER.match(l)), len(lines))
            lines.insert(i, "  build pendpost;")
        if delayed:
            pat += " [ inslot = 1; globalset(inst_next, inslot); ]"
            k = lines.index("  delayslot(1);")
            nxt = lines[k + 1].strip() if k + 1 < len(lines) else ""
            lines.insert(k + 1, "  pflag = pflag & (t == 0);" if nxt == "if (t) goto rel;" else "  pflag = 0;")
        out.append("%s%s {\n%s\n}\n%s" % (head, pat, "\n".join(lines), rest))
        if variant:
            out.append(variant)
    return "".join(out)


def main():
    os.makedirs(LANGDIR, exist_ok=True)
    gen6 = [r for r in T.INSTRUCTIONS if r["gen_min"] <= 6 <= r["gen_max"]]
    gen7 = [r for r in T.INSTRUCTIONS if r["gen_min"] <= 7 <= r["gen_max"]]
    body6 = add_pend("".join(emit_insn(r) for r in gen6))
    body7 = add_pend("".join(emit_insn(r) for r in gen7))
    hdr = "# AUTO-GENERATED instruction constructors -- do not edit.\n\n"
    open(os.path.join(LANGDIR, "qrisc.sinc"), "w").write(emit_core() + "\n" + emit_token())
    open(os.path.join(LANGDIR, "qrisc_gen6.sinc"), "w").write(hdr + body6)
    open(os.path.join(LANGDIR, "qrisc_gen7.sinc"), "w").write(hdr + body7)
    for dom in ("A6XX_CONTROL_REG", "A7XX_CONTROL_REG", "A7XX_GEN3_CONTROL_REG"):
        open(os.path.join(LANGDIR, "qrisc_creg_%s.sinc" % dom.lower()), "w").write(
            hdr + emit_regnames(dom, "@", "cbase"))
    open(os.path.join(LANGDIR, "qrisc_sreg.sinc"), "w").write(hdr + emit_regnames(T.SQE_DOMAIN, "%", "sbase"))
    for lang, dom in (("a6xx", "A6XX_CONTROL_REG"), ("a7xx", "A7XX_CONTROL_REG"),
                      ("a7xx_gen3", "A7XX_GEN3_CONTROL_REG"), ("a8xx", "A7XX_CONTROL_REG")):
        open(os.path.join(LANGDIR, "qrisc_%s.pspec" % lang), "w").write(emit_pspec(dom))
    helper = os.path.join(os.path.dirname(LANGDIR), "..", "ghidra_scripts", "QRiscFirmwareHelper.java")
    java = emit_pm4_names(open(helper).read())
    open(helper, "w").write(java)
    print("gen6 records:", len(gen6), " gen7 records:", len(gen7))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare Ghidra's decode (DumpSlots.java: "<addr> <len> <text>") with Mesa's
qrisc-disasm (raw mode, one line per 32-bit word, labels removed).
  compare.py <ghidra.txt> <mesa.txt> [--show N]          (exit 1 on unexplained differences)
Exact: same text after the register spelling ($0a -> r0a: SLEIGH names cannot contain '$'),
b0x1f as b31 (Mesa prints bit numbers in decimal; mesa_raw.py turns labels into byte addresses), and white space. Semantic: same after numbers are
canonicalised. Mesa's `; ...` register-name comments are dropped."""
import collections
import re
import sys

NUM = re.compile(r"(?<![\w.])([-+]?)(0x[0-9a-fA-F]+|\d+)(?![\w])")


def syntax(t):
    t = t.split("\t;")[0].split(" ;")[0].strip()
    # bit numbers: Mesa prints b<decimal>, Ghidra b0x<hex>
    t = re.sub(r"\bb0x([0-9a-f]+)\b", lambda m: "b%d" % int(m.group(1), 16), t)
    t = re.sub(r"\$([0-9a-f]{2})\b", r"r\1", t)
    t = t.replace("$", "")
    return re.sub(r"\s+", "", t.lower())


def num(m):
    v = int(m.group(2), 0)
    return ("-" if m.group(1) == "-" else "") + hex(v)


def norm(t):
    return NUM.sub(num, syntax(t).replace(",", " , ")).replace(" ", "")


def mn(t):
    return re.sub(r"^(\([a-z0-9]+\))+", "", t.strip()).split(" ")[0] if t else ""


EXPLAINED = [
    (r"^(sread|swrite)/(sread|swrite)$",
     "Mesa qrisc-disasm bug: a pre-incremented SQE register offset is printed as its decimal value "
     "behind a 0x prefix (0x8da shows as 0x2266; qrisc-asm reads 0x2266 back as 0x266, so the "
     "round trip fails); the module prints the value in hex"),
]


def classify(gt, mt, gl):
    gbad = gl == 0 or gt == "BAD"
    mbad = mt.startswith("[")
    if gbad and mbad:
        return "both-invalid"
    if not gbad and not mbad and syntax(gt) == syntax(mt):
        return "exact"
    if not gbad and not mbad and norm(gt) == norm(mt):
        return "semantic"
    if gbad:
        return "ghidra BAD, mesa %s" % mn(mt)
    if mbad:
        return "mesa invalid, ghidra %s" % mn(gt)
    return "%s/%s" % (mn(gt), mn(mt))


def explain(k):
    return next((why for pat, why in EXPLAINED if re.search(pat, k)), None)


def report(pairs, show=3, out=sys.stdout):
    counts, buckets, ex = collections.Counter(), collections.Counter(), collections.defaultdict(list)
    for label, (gl, gt), mt in pairs:
        k = classify(gt, mt, gl)
        if k in ("exact", "semantic", "both-invalid"):
            counts[k] += 1
            continue
        buckets[k] += 1
        if len(ex[k]) < show:
            ex[k].append("%s | %s | %s" % (label, gt, mt))
    print("%d: exact %d, semantic %d, both invalid %d, differences %d" % (
        sum(counts.values()) + sum(buckets.values()), counts["exact"], counts["semantic"],
        counts["both-invalid"], sum(buckets.values())), file=out)
    un = 0
    for k, n in sorted(buckets.items(), key=lambda kv: -kv[1]):
        tag = explain(k)
        if tag is None:
            un += n
        print("  %7d %s  [%s]" % (n, "explained: " + tag if tag else "UNEXPLAINED", k), file=out)
        for e in ex[k]:
            print("          " + e, file=out)
    print("unexplained differences: %d" % un, file=out)
    return un


def main():
    a = sys.argv[1:]
    show = 3
    if "--show" in a:
        i = a.index("--show"); show = int(a[i + 1]); del a[i:i + 2]
    gh = [l.rstrip("\n").split(" ", 2) for l in open(a[0])]
    md = [l.rstrip("\n") for l in open(a[1])]
    assert len(gh) == len(md), (len(gh), len(md))
    pairs = [("%s" % g[0], (int(g[1]), g[2] if len(g) > 2 else ""), m) for g, m in zip(gh, md)]
    sys.exit(1 if report(pairs, show) else 0)


if __name__ == "__main__":
    main()

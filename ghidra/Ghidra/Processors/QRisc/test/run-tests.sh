#!/usr/bin/env bash
# QRisc (AdrenoSQE) module test suite.
#
#   GHIDRA_INSTALL_DIR=<Ghidra 12.1.x/12.2> test/run-tests.sh [workdir]
#
# 1. the four specs (a6xx, a7xx, a7xx_gen3, a8xx) compile
# 2. decode differential against Mesa's qrisc-disasm (a black box, raw mode) for a6xx, a7xx and
#    a7xx_gen3: every value of bits 24-31 x bits 0-5 with 4 fillings, every control/SQE register
#    number of the register-access groups, plus 50,000 random words; 0 unexplained differences
# 3. every SLEIGH constructor of those languages is reached by that corpus
# 4. p-code: hand-computed emulator cases (EmuCheck.java), a6xx (35) and a7xx (41), each set with
#    one deliberately wrong expectation that must be detected
# 5. real code: Mesa's test firmware for a6xx and a7xx (real-binaries.sh): linear sweep against
#    qrisc-disasm, then flow analysis and decompilation of every function
#
# Environment: GHIDRA_INSTALL_DIR, PROJ_DIR (headless projects; no path component may start with a
# dot), QRISC_DISASM, MESA_SRC (test/build-oracles.sh builds them), QUICK=1 (10,000 random).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
: "${QRISC_DISASM:?set QRISC_DISASM (test/build-oracles.sh)}" "${MESA_SRC:?set MESA_SRC}"
export QRISC_DISASM MESA_SRC
W=$(readlink -m "${1:-${TMPDIR:-/tmp}/qrisc-tests}")
mkdir -p "$W"
export TMPDIR=$W PROJ_DIR=${PROJ_DIR:-$W}
source "$HERE/env.sh"
fail=0
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/QRisc"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then echo "warning: $P exists and is not this module" >&2; fi
# Ghidra language variant, qrisc-disasm firmware id
VERS=("a6xx 6ee" "a7xx 730" "a7xx_gen3 520")

echo "== 1. SLEIGH compiles"
for v in a6xx a7xx a7xx_gen3 a8xx; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/qrisc_$v.slaspec" 2>&1 | grep -E "^ERROR" && exit 1 || true
	echo "   qrisc_$v.sla: $(stat -c %s "$MOD/data/languages/qrisc_$v.sla") bytes"
done

RAND=50000; [[ -n ${QUICK:-} ]] && RAND=10000
python3 "$HERE/gen_corpus.py" "$W/all.bin" $RAND 1 | sed 's/^/   /'
echo "== 2. decode differential against qrisc-disasm"
for e in "${VERS[@]}"; do
	read -r lv gid <<<"$e"
	"$QRISC_DISASM" -g "$gid" -r "$W/all.bin" >"$W/mesa_$lv.raw"
	python3 "$HERE/mesa_raw.py" "$W/mesa_$lv.raw" "$W/mesa_$lv.txt"
	"$HERE/ghidra-slots.sh" "QRisc:LE:32:$lv" "$W/all.bin" 4 "$W/gh_$lv.txt"
	python3 "$HERE/compare.py" "$W/gh_$lv.txt" "$W/mesa_$lv.txt" --show 2 >"$W/compare_$lv.txt" || fail=1
	echo "   $lv: $(head -1 "$W/compare_$lv.txt" | sed 's/^[0-9]*: //'); $(tail -1 "$W/compare_$lv.txt")"
done

echo "== 3. every constructor is reached"
for e in "${VERS[@]}"; do
	read -r lv _ <<<"$e"
	"$HERE/ghidra-script.sh" raw "QRisc:LE:32:$lv" "$W/all.bin" CoverageCheck.java "$W/coverage_$lv.txt" 64 1 4
	echo "   $lv: $(tail -1 "$W/coverage_$lv.txt")"
	grep -q " 0 unreached" "$W/coverage_$lv.txt" || { grep ^unreached "$W/coverage_$lv.txt"; fail=1; }
done

echo "== 4. p-code: hand-computed emulator cases"
python3 "$HERE/emu_tests.py" "$W/emu" | sed 's/^/   /'
for lv in a6xx a7xx; do
	"$HERE/ghidra-script.sh" raw "QRisc:LE:32:$lv" "$W/emu/emu_$lv.bin" EmuCheck.java "$W/emu/tests_$lv.txt" "$W/emu/out_$lv.txt"
	echo "   $lv: $(tail -1 "$W/emu/out_$lv.txt")"
	grep -q " 0 failed, [1-9][0-9]* broken expectations detected, 0 missed" "$W/emu/out_$lv.txt" || { grep ^FAIL "$W/emu/out_$lv.txt"; fail=1; }
done

echo "== 5. real code: Mesa's test firmware"
"$HERE/real-binaries.sh" "$W/real" || fail=1
echo
((fail == 0)) && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit $fail

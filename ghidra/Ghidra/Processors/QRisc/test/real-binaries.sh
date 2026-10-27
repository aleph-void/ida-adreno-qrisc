#!/usr/bin/env bash
# Real QRisc code: Mesa's own test firmware (MIT; src/freedreno/tests/reference/qrisc_test.fw for
# a6xx and qrisc_test_a7xx.fw for a7xx, assembled from hand-written CP firmware that boots and
# handles real PM4 packets), taken from the pinned Mesa checkout that build-oracles.sh makes and
# checked against SHA-256. Nothing is committed.
#   1. linear sweep: every word of the image decoded by Ghidra (DumpSlots.java) and qrisc-disasm -r,
#      compared (compare.py)
#   2. flow analysis: each instruction stream (file word 0 stripped, as the CP and Mesa do; a7xx
#      firmware carries BR, BV and LPAC images, split by split_images.py) imported raw, the
#      bootstrap and the packet handlers marked by the module's import helper
#      (ghidra_scripts/QRiscFirmwareHelper.java), auto-analysed, every function decompiled
#      (RealCheck.java); no bad-instruction bookmarks and no decompile failures allowed
#   test/real-binaries.sh <workdir>     Environment: GHIDRA_INSTALL_DIR, QRISC_DISASM, MESA_SRC
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
: "${QRISC_DISASM:?set QRISC_DISASM}" "${MESA_SRC:?set MESA_SRC}"
W=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$W"
# file, sha256, Ghidra language, qrisc-disasm firmware id
SAMPLES=(
	"qrisc_test.fw 62d796ca1853c10346e1654e22fec5ffdf0b0574d329dbb84b4ca6dca2d6e44b a6xx 6ee"
	"qrisc_test_a7xx.fw 495815aa3de7705d33f3b62cca3d6a4dde50530b3b90fb3f951b310bee825030 a7xx 730"
)
rc=0
for s in "${SAMPLES[@]}"; do
	read -r f sum lv gid <<<"$s"
	cp "$MESA_SRC/src/freedreno/tests/reference/$f" "$f"
	echo "$sum  $f" | sha256sum -c --quiet - || { echo "checksum mismatch: $f" >&2; exit 1; }
	echo "-- $f (QRisc:LE:32:$lv)"
	"$QRISC_DISASM" -g "$gid" -r "$f" >"$f.raw"
	python3 "$HERE/mesa_raw.py" "$f.raw" "$f.mesa"
	"$HERE/ghidra-slots.sh" "QRisc:LE:32:$lv" "$f" 4 "$f.gh"
	r=$(python3 "$HERE/compare.py" "$f.gh" "$f.mesa" --show 3 >"$f.cmp" && echo ok || echo FAIL)
	echo "   linear sweep vs qrisc-disasm: $(head -1 "$f.cmp" | sed 's/^slots //') ($r)"
	[[ $r == ok ]] || rc=1
	python3 "$HERE/split_images.py" "$f" "$f.img" | sed 's/^/   /'
	for img in "$f".img.*; do
		p=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/qrisc-real.XXXXXX")
		"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$W/$img" -loader BinaryLoader \
			-processor "QRisc:LE:32:$lv" -scriptPath "$HERE;$HERE/../ghidra_scripts" -preScript QRiscFirmwareHelper.java \
			-postScript RealCheck.java "$W/$img.sum" "$W/$img.lst" "$W/$img.c" 60 -deleteProject >"$W/$img.log" 2>&1 ||
			{ tail -20 "$W/$img.log" >&2; rc=1; }
		rm -rf "$p"
		echo "   $img: $(grep -o "QRisc: jump table.*" "$W/$img.log" | sed "s/ (GhidraScript).*//; s/QRisc: //")"
		grep -E "^(functions|instructions|bad-instruction|error bookmarks|decompile|functions whose)" "$W/$img.sum" | sed 's/^/      /'
		grep -q "decompile: [0-9]* ok, 0 failed, 0 timed out" "$W/$img.sum" && grep -q "^bad-instruction bookmarks: 0" "$W/$img.sum" || rc=1
	done
done
exit $rc

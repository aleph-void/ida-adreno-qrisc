#!/usr/bin/env bash
# ghidra-slots.sh <language-id> <raw.bin> <slot> <out.txt> [ctx=val ...]   (GHIDRA_INSTALL_DIR set)
# BASE=<hex> loads the file at that address (default 0); offsets in <out.txt> stay file offsets.
set -euo pipefail
LANG_ID=$1; BIN=$(readlink -f "$2"); SLOT=$3; OUT=$(readlink -f "$4"); shift 4
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/slots.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" -loader BinaryLoader -loader-baseAddr "0x${BASE:-0}" \
	-processor "$LANG_ID" -noanalysis -scriptPath "$HERE" -postScript DumpSlots.java "$SLOT" "$OUT" "$@" \
	-deleteProject >"$PROJ/log.txt" 2>&1 || { tail -30 "$PROJ/log.txt" >&2; exit 1; }
grep -E "SCRIPT ERROR|Exception" "$PROJ/log.txt" | grep -qv "Could not compute inst_next2" && { grep -E -A5 "SCRIPT ERROR|Exception" "$PROJ/log.txt" | head -30 >&2; exit 1; }
[[ -s $OUT ]]

#!/usr/bin/env bash
# Build Mesa's freedreno QRisc tools (MIT) at a pinned commit: qrisc-disasm (the reference
# disassembler, run as a black box) and qrisc-asm (assembles the emulator cases with --rebuild).
# Needs meson, ninja, a C/C++ compiler, flex, bison and Python with mako (a venv is made).
#   test/build-oracles.sh <dir>     prints QRISC_DISASM, QRISC_ASM, MESA_SRC
set -euo pipefail
D=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$D"
[[ -d mesa ]] || git clone -q https://gitlab.freedesktop.org/mesa/mesa.git
cd mesa && git checkout -q 4bf8fd5121122abd87aafb31e43bbbe9e3d2e921
[[ -d $D/venv ]] || { python3 -m venv "$D/venv" && "$D/venv/bin/pip" -q install mako pyyaml packaging meson ninja; }
export PATH=$D/venv/bin:$PATH
[[ -d build ]] || meson setup build -Dgallium-drivers= -Dvulkan-drivers= -Dplatforms= -Dglx=disabled -Degl=disabled \
	-Dgbm=disabled -Dllvm=disabled -Dtools=freedreno -Dopengl=false -Dgles1=disabled -Dgles2=disabled \
	-Dshared-glapi=disabled -Dlibunwind=disabled -Dzstd=disabled -Dvalgrind=disabled -Dbuild-tests=false >/dev/null
ninja -C build src/freedreno/qrisc/qrisc-disasm src/freedreno/qrisc/qrisc-asm >/dev/null
echo "QRISC_DISASM=$D/mesa/build/src/freedreno/qrisc/qrisc-disasm"
echo "QRISC_ASM=$D/mesa/build/src/freedreno/qrisc/qrisc-asm"
echo "MESA_SRC=$D/mesa"

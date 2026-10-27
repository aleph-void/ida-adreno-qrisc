# Credits: AdrenoSQE (Qualcomm Adreno CP microcode, QRisc) module

This module is a community SLEIGH module that Ghidra-Rare imported, tested and fixed.
Ghidra-Rare's changes are listed below.

## Upstream

| | |
|---|---|
| Source | [locus-x64/ida-adreno-qrisc](https://github.com/locus-x64/ida-adreno-qrisc), commit `a94a1c61c98a6bf44387a56fd505bb6ba87f1408` (2026-06-28); the Ghidra module is `ghidra/Ghidra/Processors/QRisc`, its generator `ghidra/tools/qrisc_sleigh_gen.py` |
| License | MIT (`LICENSE`, Copyright 2026 adreno-qrisc contributors; a copy is in this directory) |
| Original author | Ali Raza ([@locus-x64](https://github.com/locus-x64); commits as "Ali Raza"): the whole project, including the IDA backend, the ISA table generator, the SLEIGH generator, the language files and `QRiscFirmwareHelper.java` |
| Mesa | The ISA tables (`common/qrisc_isa_tables.py`) are generated from Mesa's `src/freedreno/qrisc/qrisc.xml` and the Adreno register database (MIT, copyright Google, Valve, Rob Clark and the Mesa contributors; see the repository's `NOTICE` and `AUTHORS`). Ghidra-Rare's semantics follow Mesa's QRisc documentation (`src/freedreno/qrisc/README.rst`) and emulator (`emu.c`, `emu-regs.c`), both MIT |
| Test oracles | Mesa ([gitlab.freedesktop.org/mesa/mesa](https://gitlab.freedesktop.org/mesa/mesa) commit `4bf8fd51`, the commit upstream generated from): `qrisc-disasm` and `qrisc-asm`, run as black boxes |
| Real code | Mesa's test firmware `src/freedreno/tests/reference/qrisc_test.fw` and `qrisc_test_a7xx.fw` (MIT; upstream also ships them in `fixtures/`) |

The upstream history is kept; every Ghidra-Rare change is a separate commit on top. Ghidra-Rare
changed only the Ghidra part (`ghidra/`) and the top-level README's Ghidra rows; the IDA backend,
the Python libraries and their tests are untouched.

## Ghidra-Rare changes

1. **Built `.sla` files no longer tracked** (they are compiled by Ghidra or the build).
2. **Decoding matches `qrisc-disasm`** for a6xx, a7xx and the new a7xx gen3 language (148,304
   words each, 0 unexplained differences). In the generator (`ghidra/tools/qrisc_sleigh_gen.py`):
   - the `(rep)`, `(xmovN)`, `(peek)`, `(sdsN)` prefixes and the `!` pre-increment are displayed;
   - Mesa's aliases: `mov $r, $s` for `or $r, $00, $s`, `jump #t` for `brne $00, b0, #t`,
     `mov $r, imm << n` for `movi` (plain `mov` when the shift is 0);
   - control and SQE register operands by name (`@REG_READ_ADDR`, `%SP`, `@MEM_READ_ADDR+0x1`),
     generated from the register database for each control-register layout;
   - new language `QRisc:LE:32:a7xx_gen3` (A750 control-register layout, as Mesa's `A7XX_GEN3`).
3. **Semantics** (no pcodeop left except the packet dispatch of `waitin` and `setsecure`):
   - `$00` reads as zero;
   - `cread`/`cwrite`/`sread`/`swrite` access volatile `CREG`/`SREG` spaces (were pcodeops), with
     pre-increment updating the base register; `load`/`store` use a 64-bit `MEM` space with
     `@LOAD_STORE_HI` as the high half (were pcodeops);
   - `(rep)` loops on `$rem`; `(xmovN)` extra moves with Mesa's destination rule; `(sdsN)` extra
     source reads; reading `$data` pops a word and counts `$rem` down, `(peek)` does not;
   - `addhi`/`subhi` carry, `cmp`'s three results, unsigned `min`/`max`, `mul8`, `msb`, `rot`,
     register `setbit`, `ubfx`, `bfi` as in Mesa's emulator; `bl` sets `$lr`, `setsecure`'s
     conditional skip;
   - branches inside a delay slot (frequent in firmware; Ghidra rejected them as nested delay
     slots): decoded without a slot of their own, the branch taking effect after the next
     instruction through a pending-branch flag and context;
   - pspec per language: volatile FIFO registers and `CREG`/`SREG` blocks with every control/SQE
     register name as a label, a `bootstrap` entry at word 2; cspec: `code` added to `<global>`
     (decompilation failed on every function without it).
4. **Import helper** (`ghidra_scripts/QRiscFirmwareHelper.java`): marks the packet jump table and
   makes each handler a function named after its PM4 packet (`CP_ME_INIT`, ...; names generated
   from Mesa's `adreno_pm4.xml`), as upstream's IDA loader does.
5. **Build**: `build.gradle`, `extension.properties` (extension name `AdrenoSQE`), `LICENSE`.
6. **Docs**: `ghidra/README.md` modelling notes and limitations brought up to date, `VALIDATION.md`
   marked as the original report, top-level README's Ghidra rows; `GHIDRA-RARE.md` (this
   verification) and `test/` (the suite).

# Ghidra-Rare notes: AdrenoSQE (Qualcomm Adreno CP microcode, QRisc)

This is the Ghidra-Rare fork of the Ghidra module in
[locus-x64/ida-adreno-qrisc](https://github.com/locus-x64/ida-adreno-qrisc) (this directory,
`ghidra/Ghidra/Processors/QRisc`; extension name `AdrenoSQE`). Ghidra-Rare tested it against
Mesa's `qrisc-disasm` (MIT, run as a black box) and Mesa's QRisc documentation and emulator, and
fixed what the tests found. Authors, upstream commit and the list of changes are in
[CREDITS.md](CREDITS.md); upstream's own notes and limitations, now updated, are in
[`ghidra/README.md`](../../../README.md). It targets Ghidra 12.1.4 and also builds on 12.1.3 and
12.2; prebuilt zips are on the fork's Releases page.

## What it covers

The command processor (CP) of Adreno GPUs runs microcode in an ISA Mesa calls QRisc (formerly
afuc): the SQE firmware of a6xx and later (`*_sqe.fw`).

| Language ID | `qrisc-disasm` firmware id | Control registers |
|---|---|---|
| `QRisc:LE:32:a6xx` | `-g 6ee` (a6xx) | `A6XX_CONTROL_REG` |
| `QRisc:LE:32:a7xx` | `-g 730` (a7xx) | `A7XX_CONTROL_REG` |
| `QRisc:LE:32:a7xx_gen3` | `-g 520` (A750) | `A7XX_GEN3_CONTROL_REG` |
| `QRisc:LE:32:a8xx` | none (Mesa has no a8xx) | decoded as a7xx; unverified |

- Every instruction `qrisc-disasm` decodes, in its syntax except that registers are `r00`..`r19`,
  `sp`, `lr`, `rem`, `data`, ... (SLEIGH names cannot contain `$`), bit numbers are hex (`b0x1f`)
  and branch targets are addresses.
- Semantics: ALU with the `addhi`/`subhi` carry, `cmp`, `mul8`, `min`/`max`, `msb`, `rot`,
  bit-field and bit instructions, `$00` reading as zero, the `$data`/`$rem` packet FIFO,
  `(rep)`, `(xmovN)`, `(peek)`, `(sdsN)`, control and SQE registers as volatile address spaces
  (with names), `load`/`store` with `@LOAD_STORE_HI`, pre-increment, delay slots (also branches
  inside a delay slot), `call`/`ret` on a return stack, `bl`/`sret` through `$lr`.
- Spec files: cspec (`<global>` code, control/SQE and memory spaces; upstream's register
  convention), a pspec per language (volatile FIFO registers and register spaces, control/SQE
  register labels, `bootstrap` entry), and the import helper `ghidra_scripts/QRiscFirmwareHelper.java`
  (packet handlers named after their PM4 packets). CP firmware is not ELF and has no DWARF.

## Testing

Requirements: Ghidra (`GHIDRA_INSTALL_DIR`; the suite links this directory in as
`Ghidra/Processors/QRisc`) and Mesa's QRisc tools: `test/build-oracles.sh <dir>` clones Mesa at the
pinned commit and builds `qrisc-disasm` and `qrisc-asm` (prints `QRISC_DISASM`, `QRISC_ASM`,
`MESA_SRC`).

```
test/run-tests.sh [workdir]   # compile, decode diff, every-entry test, emulator, Mesa test firmware
```

`python3 test/emu_tests.py --rebuild $QRISC_ASM` re-assembles the emulator cases.

## Results

Identical on Ghidra 12.1.4 and 12.2.

### Decoding vs `qrisc-disasm`

`test/gen_corpus.py` writes 148,304 words: every value of bits 24-31 with every value of bits 0-5
and four fillings of the rest (65,536), every control/SQE register number in the register-access
groups (32,768), and 50,000 random words. `qrisc-disasm -r` disassembles the same file;
`test/mesa_raw.py` turns its labels into addresses.

| Language | Exact | Semantic | Both invalid | Differences |
|---|---|---|---|---|
| a6xx | 94,429 | 17,769 | 35,801 | 305, all one `qrisc-disasm` bug (below) |
| a7xx | 81,474 | 19,463 | 47,062 | 305, idem |
| a7xx_gen3 | 81,390 | 19,547 | 47,062 | 305, idem |

"Exact" maps `$NN` to `rNN`, drops `$` and Mesa's `; register` comments, and reads `bN` as
`b0xN`; "semantic" additionally canonicalises numbers.

**Every-entry test** (`CoverageCheck.java`): all constructors of every language are reached (a6xx
179, a7xx 184, a7xx_gen3 179).

### Emulator

`test/emu_tests.py` holds 35 cases for a6xx and 41 for a7xx, assembled once with `qrisc-asm`
(`test/emu/cases_*.txt`), with expectations worked out from Mesa's emulator and documentation:
`add`/`addhi` and `sub`/`subhi` carry chains, immediates, `mov` aliases, `movi` shifts, the three
`cmp` results, `mul8`, unsigned `min`/`max`, `msb`, `rot`, shifts, `not`, `setbit`/`clrbit`,
`$00` reading as zero, taken/not-taken branches with their delay slot, a branch in a delay slot
(each case of which one is taken), `jump; jump`, Mesa's test-firmware `gcd` routine (a chain of
branches each in the previous one's slot), `call`/`ret`, `$data` popping `$rem`, `(rep)` with and
without `$data`, `(xmov1)` to a plain register (discarded), `(xmov2)` to `$addr`, control-register
and memory round trips, pre-increment; on a7xx also `bl`/`sret`, `ubfx`, `bfi`, `bic`, register
`setbit`, `(peek)`, `(rep)(sds2)`. Result: all pass, and the deliberately wrong expectation of
each set is reported.

### Real code

`test/real-binaries.sh` takes Mesa's test firmware (MIT; hand-written CP firmware that boots and
handles PM4 packets, assembled by Mesa) from the pinned Mesa checkout, checks SHA-256, and runs
(1) a linear sweep of every word through both tools and (2) a raw import of each instruction
stream (BR, and on a7xx the BV and LPAC images) with the import helper, auto-analysis and
decompilation of every function.

| Firmware | Language | Linear sweep vs `qrisc-disasm` | Functions | Bad instr. | Decompiled |
|---|---|---|---|---|---|
| `qrisc_test.fw` | a6xx | 258 words, 0 differences | 14 | 0 | 14 / 14 |
| `qrisc_test_a7xx.fw` BR | a7xx | 602 words (all images), 0 differences | 14 | 0 | 14 / 14 |
| `qrisc_test_a7xx.fw` BV | a7xx | | 2 | 0 | 2 / 2 |
| `qrisc_test_a7xx.fw` LPAC | a7xx | | 2 | 0 | 2 / 2 |

Handlers come out named as in Mesa's listing (`CP_ME_INIT`, `CP_MEM_WRITE`, `CP_SET_DRAW_STATE`,
...), and the `gcd` routine with branches in delay slots decompiles to its loop. Tested locally on
vendor firmware as well. No freely licensed production firmware exists.

## Known gaps

- **Both branches taken**: when a branch sits in the delay slot of a taken branch and is itself
  taken, the CP runs one instruction at the first target and then goes to the second; the module
  goes to the first target only (Ghidra cannot nest delay slots, and the instruction at the first
  target is not known to the branch). Firmware uses this for exclusive conditions (two-way
  splits, `breq` chains, `jump; jump`), where it does not occur.
- **One decoding per address**: a branch that is both in a delay slot and the target of another
  branch is decoded the way the first flow reaching it needs; the other flow then gets a
  conflicting-context error bookmark. The semantics of the in-slot decoding are also right for a
  direct entry, so it only matters for which flow comes first.
- **Hardware outside the core**: `waitin` (dispatch of the next packet through the CP's internal
  packet table) and `setsecure` (secure-mode switch; Mesa does not know when it skips) are
  pcodeops; `$memdata`/`$regdata` are volatile reads of the memory/register read queues that the
  hardware fills from `@MEM_READ_*`/`@REG_READ_*` asynchronously, and `$addr`/`$usraddr`/`$data`
  writes are volatile writes into the GPU register write path; the `(sds)` draw-state RAM is
  internal to the CP.
- **Calling convention**: upstream's cspec (arguments `r02`-`r04`) is kept; firmware routines
  have no fixed convention, so it is unverified.
- **Import layout**: the helper expects the version word, then the jump-table offset, then the
  bootstrap (Mesa's test firmware layout); a7xx BV/LPAC images are imported separately
  (`test/split_images.py` shows how they follow the BR image).

## Unverified

- `QRisc:LE:32:a8xx`: Mesa has no a8xx support, so there is no oracle; it decodes as a7xx.
- Hardware behaviour beyond Mesa's documentation and emulator; where the two differ the module
  follows the documentation: `(xmovN)` moves are discarded unless the destination is `$addr`,
  `$usraddr` or `$data` (the emulator always writes `$data`), and each `$data` read counts `$rem`
  down also inside `(rep)(sdsN)` (the emulator's `(rep)` resets `$rem` to its start value minus one).

## Confirmed reference-tool bugs

- `qrisc-disasm` prints a pre-incremented `sread`/`swrite` SQE register offset as its decimal value
  behind a `0x` prefix (an offset 0x8da shows as `0x2266`); `qrisc-asm` reads `0x2266` back as
  0x266, so the round trip fails. The module prints the value in hex. These are the 305
  differences per language.

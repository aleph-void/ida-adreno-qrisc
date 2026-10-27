# QRisc (Adreno afuc) Ghidra SLEIGH module

A Ghidra processor module + decompiler for the Adreno CP microcode ISA Mesa
calls `afuc` / `QRisc` (SQE / PFP / PM4 firmware). Ghidra's decompiler runs
on SLEIGH-generated p-code, so this module gives you disassembly and a
decompiler. IDA can't, because Hex-Rays exposes no third-party API for
custom-ISA decompilation.

Generated from Mesa `qrisc.xml` (isaspec), pinned at
`4bf8fd5121122abd87aafb31e43bbbe9e3d2e921`, via `common/qrisc_isa_tables.py`.

This is the Ghidra-Rare fork of the module (extension name `AdrenoSQE`): see
[`GHIDRA-RARE.md`](Ghidra/Processors/QRisc/GHIDRA-RARE.md) for what was
changed and how it is verified, and the fork's Releases page for prebuilt
extension zips for Ghidra 12.1.3, 12.1.4 and 12.2.

## Supported generations

| Language id          | Adreno gen | Status |
|----------------------|-----------|--------|
| `QRisc:LE:32:a6xx`   | a6xx (unified SQE)          | validated against Mesa oracle |
| `QRisc:LE:32:a7xx`   | a7xx (split BR/BV + LPAC)   | validated against Mesa oracle |
| `QRisc:LE:32:a7xx_gen3` | a7xx gen3 (A750 control-register layout) | validated against Mesa oracle |
| `QRisc:LE:32:a8xx`   | a8xx                        | best-effort; same ISA family as a7xx, decoded with the a7xx constructor set. Any a8xx-only opcodes/control-regs need RE. |

a5xx is intentionally out of scope.

## Install

Prebuilt: install the `AdrenoSQE` zip from the Releases page with
File > Install Extensions (Ghidra 12.1.3, 12.1.4, 12.2) and restart Ghidra.

From source:

1. `cp -r ghidra/Ghidra/Processors/QRisc <GHIDRA>/Ghidra/Processors/QRisc`
2. Restart Ghidra. The four QRisc languages appear under processor "QRisc"
   (the `.sla` files are compiled on first use; they are not kept in git).

Or build the extension zip: `cd ghidra/Ghidra/Processors/QRisc &&
GHIDRA_INSTALL_DIR=<GHIDRA> gradle buildExtension`.

Rebuild the `.sla` after editing a spec:
`<GHIDRA>/support/sleigh Ghidra/Processors/QRisc/data/languages/qrisc_a6xx.slaspec`
(and a7xx / a7xx_gen3 / a8xx).

Regenerate the SLEIGH from the ISA tables (tracks Mesa upstream):
`python3 ghidra/tools/qrisc_sleigh_gen.py`

## Importing firmware

CP firmware files (`a630_sqe.fw`, `gen70900_sqe.fw`, ...) begin with a leading
file word the running CP skips; the version NOP and instruction stream begin
at file **word 1** (matching Mesa `qrisc-disasm`, which does
`instrs = &buf[1]`).

Single-SQE quick path:

1. Strip the leading word: `tail -c +5 a630_sqe.fw > a630.stream`
2. **Import File** -> `a630.stream`, Language `QRisc:LE:32:a6xx`
   (a730/gen705xx -> a7xx; A750/gen709xx -> a7xx_gen3; gen80xxx -> a8xx), base `0x0`.
3. Run the **QRiscFirmwareHelper** script (category QRisc): marks the
   version/jumptbl NOPs as data, reports the packet jump-table offset,
   disassembles `bootstrap` at word 2, and makes every packet handler of the
   jump table a function named after its PM4 packet (`CP_ME_INIT`, ...).
   Firmware whose header does not hold the jump-table offset in word 1 gets
   the bootstrap only; set further entry points by hand.

a7xx/a8xx blobs bundle BR + BV (+ LPAC) in one `_sqe.fw`. Splitting is in
`common/qrisc_bootstrap.py`; import each sub-image separately or extend the
helper.

GMU firmware (`*_gmu.bin`) is a separate ARM Cortex-M core, not QRisc. Load
with `ARM:LE:32:Cortex`. ZAP shaders are signed PIL/MDT blobs (afuc + ir3).

## Modeling notes

- Registers display as `r00`..`r19`, `sp`, `lr`. SLEIGH identifiers can't use
  `$`; Mesa shows `$00`..`$1b`. `$00` reads as zero (Mesa: "it reads 0 and
  writes are discarded").
- `data`, `memdata`, `regdata`, `addr`, `usraddr`, `rem` are volatile
  pseudo-registers so FIFO reads / GPU register writes survive optimization
  and read like MMIO (`r5 = data;`). Reading `$data` pops a packet word and
  counts `$rem` down; `(peek)` reads it without either.
- `cread`/`cwrite` and `sread`/`swrite` access the control and SQE registers
  as volatile `CREG`/`SREG` spaces (register number * 4), with Mesa's register
  names as labels; `load`/`store` use the `MEM` space with the high address
  half from `@LOAD_STORE_HI`. Pre-increment (`!`) updates the base register.
- Branch delay slots use SLEIGH `delayslot(1)`. A branch inside another
  branch's delay slot (common in firmware) is decoded without a slot of its
  own and takes effect after the following instruction, as the CP does; only
  the case where both branches are taken (the second target after one
  instruction at the first) is not followed.
- `call`/`bl` push a return on synthetic `hwstack` (cspec sp `csp`) and use
  p-code `call`; `ret`/`sret` return; `jumpr` is a computed goto; `waitin`
  dispatches to the next packet's handler through the CP's packet table
  (`qrisc_waitin`), `setsecure` switches secure mode (`qrisc_setsecure`).
- `(rep)` repeats while `$rem` != 0, `(xmovN)` adds up to N moves (to `$data`
  only when the destination is `$addr`, `$usraddr` or `$data`), `(sdsN)`
  reads the source N more times. `or $00` displays as `mov`, `brne $00, b0` as
  `jump`, `movi` as `mov $r, imm << n`, control/SQE registers by name, as
  Mesa's `qrisc-disasm` does.

## Validate

`Ghidra/Processors/QRisc/test/run-tests.sh` (see
[`GHIDRA-RARE.md`](Ghidra/Processors/QRisc/GHIDRA-RARE.md)): decode
differential against Mesa's `qrisc-disasm` on 148,304 words per language,
every constructor reached, hand-computed emulator cases, and Mesa's test
firmware analysed and decompiled. `VALIDATION.md` is the original v1 report.

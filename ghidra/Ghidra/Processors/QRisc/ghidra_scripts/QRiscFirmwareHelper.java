// QRiscFirmwareHelper -- post-import setup for an Adreno SQE/PFP/PM4 firmware
// blob that has been imported raw (BinaryLoader, base 0x0) with a QRisc language.
//
// Assumes the imported image is the INSTRUCTION STREAM with the leading file
// word (word0) already stripped, i.e. image word0 = version NOP, word1 = packet
// jump-table offset NOP, word2 = first real instruction (the bootstrap routine).
// This matches Mesa qrisc-disasm, which does `instrs = &buf[1]`.
//
// What it does:
//   * marks the 2 leading NOP-payload words (version, jumptbl offset) as data
//   * creates and disassembles an entry point "bootstrap" at word2 (byte 8)
//   * reports the packet jump-table offset encoded in word1[0:15]
//   * marks the 0x80-entry packet jump table as data and makes every handler it
//     names a function, labelled with the PM4 packet name (CP_*) of its index
//     for the language's generation, or UNKN<n> like Mesa's qrisc-disasm
//
// Firmware whose header differs from this layout (no usable jump-table offset in
// word1) gets the bootstrap entry only.
//
// Full container parsing (KGSL extra-dword detection, BR/BV/LPAC sub-image
// splitting) lives in the shared container library (common/, Stage 3); see
// ghidra/README.md for the recommended end-to-end import flow.
//
// @category QRisc
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class QRiscFirmwareHelper extends GhidraScript {

    // BEGIN GENERATED PM4 NAMES (ghidra/tools/qrisc_sleigh_gen.py; Mesa adreno_pm4.xml, MIT)
    static final String[] PM4_GEN6 = {
        null, null, null, null,
        "PKT4", null, null, null,
        null, null, "IN_IB_END", "IN_GMU_INTERRUPT",
        null, null, null, "IN_PREEMPT",
        "CP_NOP", "CP_RECORD_PFP_TIMESTAMP", "CP_WAIT_MEM_WRITES", "CP_WAIT_FOR_ME",
        "CP_WAIT_MEM_GTE", null, null, null,
        null, "CP_DRAW_PRED_ENABLE_GLOBAL", "CP_DRAW_PRED_ENABLE_LOCAL", null,
        null, "CP_SKIP_IB2_ENABLE_GLOBAL", null, null,
        null, "CP_REG_RMW", "CP_DRAW_INDX", "CP_SKIP_IB2_ENABLE_LOCAL",
        "CP_DRAW_AUTO", "CP_SET_STATE", "CP_WAIT_FOR_IDLE", null,
        "CP_DRAW_INDIRECT", "CP_DRAW_INDX_INDIRECT", "CP_DRAW_INDIRECT_MULTI", null,
        "CP_BLIT", null, "CP_SET_BIN_DATA5_OFFSET", "CP_SET_BIN_DATA5",
        null, "CP_RUN_OPENCL", "CP_LOAD_STATE6_GEOM", "CP_EXEC_CS",
        "CP_LOAD_STATE6_FRAG", "CP_SET_SUBDRAW_SIZE", "CP_LOAD_STATE6", "CP_INDIRECT_BUFFER_PFD",
        "CP_DRAW_INDX_OFFSET", "CP_REG_TEST", null, "CP_INVALIDATE_STATE",
        "CP_WAIT_REG_MEM", "CP_MEM_WRITE", "CP_REG_TO_MEM", "CP_INDIRECT_BUFFER",
        "CP_INTERRUPT", "CP_EXEC_CS_INDIRECT", "CP_MEM_TO_REG", "CP_SET_DRAW_STATE",
        "CP_COND_EXEC", "CP_COND_WRITE5", "CP_EVENT_WRITE", "CP_COND_REG_EXEC",
        "CP_ME_INIT", null, "CP_REG_TO_SCRATCH", "CP_SET_DRAW_INIT_FLAGS",
        "CP_SCRATCH_WRITE", "CP_SCRATCH_TO_REG", "CP_DRAW_PRED_SET", "CP_MEM_WRITE_CNTR",
        "CP_START_BIN", "CP_END_BIN", "CP_WAIT_REG_EQ", "CP_SMMU_TABLE_UPDATE",
        "CP_CONTEXT_SWITCH", "CP_SET_AMBLE", "CP_SET_PSEUDO_REG", "CP_INDIRECT_BUFFER_CHAIN",
        null, null, null, null,
        "CP_CONTEXT_REG_BUNCH", null, "CP_CONTEXT_UPDATE", "CP_SET_PROTECTED_MODE",
        null, null, "CP_WHERE_AM_I", "CP_SET_MODE",
        "CP_SET_VISIBILITY_OVERRIDE", "CP_SET_MARKER", "CP_SET_SECURE_MODE", null,
        null, null, null, "CP_CONTEXT_SWITCH_YIELD",
        "CP_PREEMPT_DISABLE", "CP_REG_WRITE", null, "CP_BOOTSTRAP_UCODE",
        "CP_WAIT_TWO_REGS", "CP_TEST_TWO_MEMS", "CP_REG_TO_MEM_OFFSET_REG", "CP_MEM_TO_MEM",
        "CP_REG_TO_MEM_OFFSET_MEM", "CP_MEMCPY", null, null,
        "CP_REG_WR_NO_CTXT", null, null, null,
        null, null, null, null,
    };
    static final String[] PM4_GEN7 = {
        null, null, null, null,
        "PKT4", null, null, null,
        null, null, "IN_IB_END", "IN_GMU_INTERRUPT",
        null, null, null, "IN_PREEMPT",
        "CP_NOP", "CP_RECORD_PFP_TIMESTAMP", "CP_WAIT_MEM_WRITES", "CP_WAIT_FOR_ME",
        "CP_WAIT_TIMESTAMP", "CP_GLOBAL_TIMESTAMP", "CP_LOCAL_TIMESTAMP", "CP_THREAD_CONTROL",
        "CP_RESOURCE_LIST", "CP_DRAW_PRED_ENABLE_GLOBAL", "CP_DRAW_PRED_ENABLE_LOCAL", "CP_BV_BR_COUNT_OPS",
        "CP_MODIFY_TIMESTAMP", "CP_SKIP_IB2_ENABLE_GLOBAL", null, "CP_RESET_CONTEXT_STATE",
        null, "CP_REG_RMW", "CP_DRAW_INDX", "CP_SKIP_IB2_ENABLE_LOCAL",
        "CP_DRAW_AUTO", "CP_SET_STATE", "CP_WAIT_FOR_IDLE", "CP_SKIP_IB_MODE",
        "CP_DRAW_INDIRECT", "CP_DRAW_INDX_INDIRECT", "CP_DRAW_INDIRECT_MULTI", null,
        "CP_BLIT", "CP_SET_UNK_BIN_DATA", "CP_SET_BIN_DATA5_OFFSET", "CP_SET_BIN_DATA5",
        null, "CP_RUN_OPENCL", "CP_LOAD_STATE6_GEOM", "CP_EXEC_CS",
        "CP_LOAD_STATE6_FRAG", "CP_SET_SUBDRAW_SIZE", "CP_LOAD_STATE6", "CP_INDIRECT_BUFFER_PFD",
        "CP_DRAW_INDX_OFFSET", "CP_REG_TEST", "CP_CCHE_INVALIDATE", "CP_INVALIDATE_STATE",
        "CP_WAIT_REG_MEM", "CP_MEM_WRITE", "CP_REG_TO_MEM", "CP_INDIRECT_BUFFER",
        "CP_INTERRUPT", "CP_EXEC_CS_INDIRECT", "CP_MEM_TO_REG", "CP_SET_DRAW_STATE",
        "CP_COND_EXEC", "CP_COND_WRITE5", "CP_EVENT_WRITE7", "CP_COND_REG_EXEC",
        "CP_ME_INIT", "CP_MEM_TO_SCRATCH_MEM", "CP_REG_TO_SCRATCH", "CP_SET_DRAW_INIT_FLAGS",
        "CP_SCRATCH_WRITE", "CP_SCRATCH_TO_REG", "CP_DRAW_PRED_SET", "CP_MEM_WRITE_CNTR",
        "CP_START_BIN", "CP_END_BIN", "CP_WAIT_REG_EQ", "CP_SMMU_TABLE_UPDATE",
        null, "CP_SET_AMBLE", "CP_SET_PSEUDO_REG", "CP_INDIRECT_BUFFER_CHAIN",
        null, null, null, null,
        "CP_CONTEXT_REG_BUNCH", "CP_NON_CONTEXT_REG_BUNCH", "CP_CONTEXT_UPDATE", "CP_SET_PROTECTED_MODE",
        null, null, "CP_WHERE_AM_I", "CP_SET_MODE",
        "CP_SET_VISIBILITY_OVERRIDE", "CP_SET_MARKER", "CP_SET_SECURE_MODE", null,
        null, null, null, "CP_CONTEXT_SWITCH_YIELD",
        "CP_SCOPE_CNTL", null, null, "CP_BOOTSTRAP_UCODE",
        null, "CP_TEST_TWO_MEMS", "CP_REG_TO_MEM_OFFSET_REG", "CP_MEM_TO_MEM",
        "CP_REG_TO_MEM_OFFSET_MEM", "CP_MEMCPY", null, null,
        "CP_REG_WR_NO_CTXT", null, null, null,
        null, null, null, "CP_FIXED_STRIDE_DRAW_TABLE",
    };
    static final String[] PM4_GEN8 = {
        null, null, null, null,
        "PKT4", null, null, null,
        null, null, "IN_IB_END", "IN_GMU_INTERRUPT",
        null, null, null, "IN_PREEMPT",
        "CP_NOP", "CP_RECORD_PFP_TIMESTAMP", "CP_WAIT_MEM_WRITES", "CP_WAIT_FOR_ME",
        "CP_WAIT_TIMESTAMP", "CP_GLOBAL_TIMESTAMP", "CP_LOCAL_TIMESTAMP", "CP_THREAD_CONTROL",
        "CP_RESOURCE_LIST", "CP_DRAW_PRED_ENABLE_GLOBAL", "CP_DRAW_PRED_ENABLE_LOCAL", "CP_BV_BR_COUNT_OPS",
        "CP_MODIFY_TIMESTAMP", "CP_SKIP_IB2_ENABLE_GLOBAL", null, "CP_RESET_CONTEXT_STATE",
        null, "CP_REG_RMW", "CP_DRAW_INDX", "CP_SKIP_IB2_ENABLE_LOCAL",
        "CP_DRAW_AUTO", "CP_SET_STATE", "CP_WAIT_FOR_IDLE", "CP_SKIP_IB_MODE",
        "CP_DRAW_INDIRECT", "CP_DRAW_INDX_INDIRECT", "CP_DRAW_INDIRECT_MULTI", null,
        "CP_BLIT", "CP_SET_UNK_BIN_DATA", "CP_SET_BIN_DATA5_OFFSET", "CP_SET_BIN_DATA5",
        null, "CP_RUN_OPENCL", "CP_LOAD_STATE6_GEOM", "CP_EXEC_CS",
        "CP_LOAD_STATE6_FRAG", "CP_SET_SUBDRAW_SIZE", "CP_LOAD_STATE6", "CP_INDIRECT_BUFFER_PFD",
        "CP_DRAW_INDX_OFFSET", "CP_REG_TEST", "CP_CCHE_INVALIDATE", "CP_INVALIDATE_STATE",
        "CP_WAIT_REG_MEM", "CP_MEM_WRITE", "CP_REG_TO_MEM", "CP_INDIRECT_BUFFER",
        "CP_INTERRUPT", "CP_EXEC_CS_INDIRECT", "CP_MEM_TO_REG", "CP_SET_DRAW_STATE",
        "CP_COND_EXEC", "CP_COND_WRITE5", "CP_EVENT_WRITE7", "CP_COND_REG_EXEC",
        "CP_ME_INIT", "CP_MEM_TO_SCRATCH_MEM", "CP_REG_TO_SCRATCH", "CP_SET_DRAW_INIT_FLAGS",
        "CP_SCRATCH_WRITE", "CP_SCRATCH_TO_REG", "CP_DRAW_PRED_SET", "CP_MEM_WRITE_CNTR",
        "CP_START_BIN", "CP_END_BIN", "CP_WAIT_REG_EQ", "CP_SMMU_TABLE_UPDATE",
        null, "CP_SET_AMBLE", "CP_SET_PSEUDO_REG", "CP_INDIRECT_BUFFER_CHAIN",
        "CP_MEMORY_MAP_UPDATE", "CP_BARRIER", null, null,
        "CP_CONTEXT_REG_BUNCH", "CP_NON_CONTEXT_REG_BUNCH", "CP_CONTEXT_UPDATE", "CP_SET_PROTECTED_MODE",
        null, null, "CP_WHERE_AM_I", "CP_SET_MODE",
        "CP_SET_VISIBILITY_OVERRIDE", "CP_SET_MARKER", "CP_SET_SECURE_MODE", null,
        null, null, null, "CP_CONTEXT_SWITCH_YIELD",
        "CP_SCOPE_CNTL", null, null, "CP_BOOTSTRAP_UCODE",
        null, "CP_TEST_TWO_MEMS", "CP_REG_TO_MEM_OFFSET_REG", "CP_MEM_TO_MEM",
        "CP_REG_TO_MEM_OFFSET_MEM", "CP_MEMCPY", null, null,
        "CP_REG_WR_NO_CTXT", null, null, null,
        null, null, null, "CP_FIXED_STRIDE_DRAW_TABLE",
    };
    // END GENERATED PM4 NAMES

    @Override
    public void run() throws Exception {
        Address base = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(0);
        Address version = base;
        Address jumptbl = base.add(4);
        Address boot = base.add(8);
        long words = currentProgram.getMemory().getBlock(base).getSize() / 4;

        // version + jumptbl-offset are NOP payloads read as data by the bootstrap.
        clearListing(version, jumptbl.add(3));
        createData(version, new DWordDataType());
        createData(jumptbl, new DWordDataType());
        setEOLComment(version, "firmware id / version (NOP payload)");

        int jtoff = getInt(jumptbl) & 0xffff;
        setEOLComment(jumptbl, "packet jump-table word offset = 0x" +
                Integer.toHexString(jtoff));
        println("QRisc: packet jump-table at word 0x" + Integer.toHexString(jtoff) +
                " (byte 0x" + Integer.toHexString(jtoff * 4) + ")");

        DisassembleCommand cmd = new DisassembleCommand(boot, null, true);
        cmd.applyTo(currentProgram, monitor);
        if (getFunctionAt(boot) == null) {
            createFunction(boot, "bootstrap");
        }
        createLabel(boot, "bootstrap", true);
        println("QRisc: disassembled bootstrap routine at " + boot);

        // packet handlers: index -> handler word, for a table that fits the image
        if (jtoff < 2 || jtoff + 0x80 > words) {
            println("QRisc: no packet jump table at that offset; handlers not marked");
            return;
        }
        String lang = currentProgram.getLanguageID().getIdAsString();
        String[] names = lang.endsWith("a6xx") ? PM4_GEN6 : lang.endsWith("a8xx") ? PM4_GEN8 : PM4_GEN7;
        TreeMap<Long, String> handlers = new TreeMap<>();
        for (int i = 0; i < 0x80; i++) {
            Address a = base.add(4L * (jtoff + i));
            long target = getInt(a) & 0xffffffffL;
            createData(a, new DWordDataType());
            if (target < 2 || target >= jtoff) {
                continue;
            }
            String name = names[i] != null ? names[i] : "UNKN" + i;
            setEOLComment(a, name);
            Address h = base.add(4 * target);
            createLabel(h, name, false, SourceType.ANALYSIS);
            handlers.merge(target, name, (old, n) -> old.startsWith("UNKN") ? n : old);
        }
        createLabel(base.add(4L * jtoff), "jumptbl", true);
        for (var e : handlers.entrySet()) {
            Address h = base.add(4 * e.getKey());
            disassemble(h);
            Function f = getFunctionAt(h);
            if (f == null) {
                f = createFunction(h, e.getValue());
            }
            if (f != null) {
                f.setName(e.getValue(), SourceType.ANALYSIS);
            }
        }
        println(String.format("QRisc: jump table at word 0x%x, %d handlers", jtoff, handlers.size()));
    }
}

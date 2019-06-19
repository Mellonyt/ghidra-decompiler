/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Creates a selection in the current program consisting of the sum
//of all function bodies.
//@category Selection

import java.io.IOException;
import java.util.*;     // Map & List

import javax.lang.model.util.ElementScanner6;

import java.lang.Math;
import java.lang.Object;
import java.text.DecimalFormat;

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;    //CodeBlock && CodeBlockImpl
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;

import ghidra.program.model.mem.*;

import ghidra.program.database.*;
import ghidra.program.database.function.*;
import ghidra.program.database.code.*;


import ghidra.util.task.TaskMonitor;    // TaskMonitor
import ghidra.app.script.GhidraScript;


public class SymbolicVSA extends GhidraScript {
    private Program program;
    private Listing listing;

    @Override
    public void run() {
        HardwareArch arch = new LArchX86();
        program = state.getCurrentProgram();
        listing = program.getListing();

        MemoryBlock[] blocks = program.getMemory().getBlocks();
        Address start, end;
        long startVM = 1, endVM = 0;    // startVM = (unsigned long) -1

        for (MemoryBlock blk: blocks) {
            /* An ELF file always has several code sections. If yes, we assume they are layed continuously */
            if (!(blk.isExecute() && blk.isInitialized() && blk.isLoaded())) continue;

            start = blk.getStart();
            end = blk.getEnd();

            if (startVM > endVM) {  // This means we find the first code section
                startVM = start.getOffset();
                endVM = end.getOffset();
                continue;
            }


            /* considering code alignment, default to 16 bytes */
            if (endVM < end.getOffset() && start.getOffset() <= (endVM + 15 >> 4 << 4)) {
                endVM = end.getOffset();
            }
            else {
                println(String.format("87: Find a non-continuous section: %s: 0x%x - 0x%x", blk.getName(), start.getOffset(), end.getOffset()));
            }
        }

        println(String.format("87: code segment: 0x%x - 0x%x", startVM, endVM));

        /* travese all functions */
        FunctionIterator iter = listing.getFunctions(true);
        FunctionSMAR smar;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            Address f_startVM, f_endVM;

            f_startVM = f.getBody().getMinAddress();
            f_endVM = f.getBody().getMaxAddress();

            /* skip all functions out the address space of current segment */
            if (f_startVM.getOffset() < startVM ||  f_endVM.getOffset() > endVM) continue;

            // Entry-point
            if (f.getEntryPoint().getOffset() != 0x400546)
                continue;

            println("Function Entry: " + f.getEntryPoint());
            println("Function Name: " + f.getName());

            smar = new FunctionSMAR(arch, program, listing, f, monitor);
            smar.doRecording();

            Map<Long, Map<String, Set<String>>> smart = smar.getSMARTable();

            println(smart.toString());
        }
    }


    boolean mergeVSATables() {
        //for (BlockSMAR blk: m_blocks) {
        //Map<String, Set<String>> table = blk.getVSATable();

        /* merge two tables */
        //}
        return true;
    }

    boolean structAnalysis() {
        return true;
    }
}

/*
   Function-level symbolic memory access recording (SMAR)
   Every symbolic value defines a domain
   */
class FunctionSMAR {
    private final HardwareArch m_arch;
    private final Program m_program;
    private final Listing m_listDB;
    private final Function m_function;
    private TaskMonitor m_monitor;

    private Map<Long, Map<String, Set<String>>> m_SMARTable;   // The function-level memory-access table
    private Map<Address, BlockSMAR> m_blocks;           // All blocks in this function

    private HashMap<String, String> m_registers;        // Track register status
    private HashMap<String, String> m_memories;         // Track memory status


    public FunctionSMAR(HardwareArch arch, Program program, Listing listintDB, Function func, TaskMonitor monitor) {
        m_arch = arch;
        m_program = program;
        m_listDB = listintDB;
        m_function = func;
        m_monitor = monitor;

        constructCFG();
    }

    /**
     * Construct the CFG for all basic blocks
     */
    private void constructCFG() {
        if (m_blocks == null) m_blocks = new HashMap<Address, BlockSMAR>();       // Basic Blocks of this function

        try {
            /* Create BlockSMAR for each codeblock */
            CodeBlockModel blkModel = new BasicBlockModel(m_program);
            AddressSetView addrSV = m_function.getBody();
            CodeBlockIterator codeblkIt = blkModel.getCodeBlocksContaining(addrSV, m_monitor);

            while (codeblkIt.hasNext()) {
                CodeBlock codeBlk = codeblkIt.next();
                BlockSMAR smarBlk = new BlockSMAR(m_arch, m_program, m_listDB, m_function, codeBlk);
                Address addrStart = codeBlk.getFirstStartAddress();
                m_blocks.put(addrStart, smarBlk);
                System.out.println("178: add smart block : " + smarBlk.toString() );
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to obtain Ghidra's basic blocks of function " + m_function.getName());
        }


        try {
            /* Create control-flow graph */
            for (BlockSMAR curSMARBlk: m_blocks.values()) {
                /* find the next-blocks of current code-block */
                Set<BlockSMAR> nxtSMARblks = new HashSet<BlockSMAR>();
                CodeBlock curCodeBlk = curSMARBlk.getCodeBlock();
                CodeBlockReferenceIterator di = curCodeBlk.getDestinations(m_monitor);
                while (di.hasNext())  {
                    CodeBlockReference ref = di.next();
                    CodeBlock nxtCodeBlk = ref.getDestinationBlock();
                    Address addrStart = nxtCodeBlk.getFirstStartAddress();
                    BlockSMAR nxtSMARBlk = m_blocks.get(addrStart);
                    if (nxtSMARBlk != null) {
                        nxtSMARblks.add(nxtSMARBlk);
                    }
                }

                /* set the m_next filed of current SMARTblock */
                curSMARBlk.setNexts(nxtSMARblks);
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to contruct the CFG for function " + m_function.getName());
        }

        if (m_blocks != null) System.out.println("not null?" + m_blocks.toString() );
    }


    /**
     * Initialize the CPUstate before interpreting current function
     */
    private void InitMachineStatus() {
        /* Set register values to symbolic initial values */
        if (m_registers == null) m_registers = new HashMap<String, String>();        // CPU State : Registers
        String[] allRegs = m_arch.getAllRegisters();

        for (String reg: allRegs) {
            m_registers.put(reg, "V" + reg);
        }

        /* Doesn't need to initialize memory state */
        if (m_memories == null) m_memories = new HashMap<String, String>();         // CPU State : Memory slot
    }


    /**
     *  Do symbolic memory access recording for current function. Apply the VSA algorithm.
     * @return
     */
    public boolean doRecording() {
        /* Obtain the wrapper object for GHIDRA's basic block */
        Address fentry = m_function.getEntryPoint();
        BlockSMAR firstBlk = m_blocks.get(fentry);
        System.out.println(m_blocks.toString());
        System.out.println(fentry.toString());
        assert(firstBlk != null);

        /* Initialize the CPU state */
        InitMachineStatus();
        firstBlk.setCPUState(m_registers, m_memories);

        try {
            /* loop until no changes to symbolic state */
            BlockSMAR smarBlk;
            boolean bDirty;
            int nState;
            int nTick = 0;
            while (true) {
                /* Test if there are blocks have CPUstate to run? */
                smarBlk = null;
                for (BlockSMAR blk: m_blocks.values()) {
                    nState = blk.getNumOfCPUState();
                    bDirty = blk.isDirty();

                    if (nState > 0 && bDirty) {
                        smarBlk = blk;
                        break;
                    }
                }

                if (smarBlk == null)  break;

                /* smarBlk != null */
                System.out.println("265: Start round traversing");
                traverseBlocksOnce(smarBlk);
                System.out.println("266: End round traversing");
                nTick ++;
                if (nTick > 8) break;
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.out.println("272: Failed to traversBlocks: " + e.toString());
        }
        return true;
    }


    /**
     * traverse all code-blocks recusively in depth-first search (DFS) order
     * @param start_block: The block for starting traversing
     * @return
     */
    private boolean traverseBlocksOnce(BlockSMAR start_block) {
        /* set all blocks un-visted */
        for (BlockSMAR blk: m_blocks.values()) {
            blk.m_bVisted = false;
        }

        start_block.runControlFlowOnce();
        return true;
    }


    /**
     * Fetch SMART from each BlockSMAR.
     * @return : the SMAR-table
     */
    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        if (m_SMARTable == null) {
            m_SMARTable = new HashMap<Long, Map<String, Set<String>>>();   // Symbolic Store
        }

        m_SMARTable.clear();

        /* fetch SMART from each block */
        Map<Long, Map<String, Set<String>>> smart;

        for (BlockSMAR blk: m_blocks.values()) {
            smart = blk.getSMARTable();

            if (smart != null) m_SMARTable.putAll(smart);
        }
        return  m_SMARTable;
    }
}


/* Basic block Representation for a given function, a wrapper of Ghidra's basic block */
class BlockSMAR {
    private HardwareArch m_arch;
    private Program m_program;
    private Listing m_listDB;
    private Function m_function;
    private CodeBlock m_block;          // Ghidra's basic block

    private Set<BlockSMAR> m_nexts;     // A set of successors
    public boolean m_bVisted;           // Visted in current cycle

    public boolean m_dirtySMART;        // The SMRT table is diry, means current block needs a new round of recording if also have CPUState

    /* SMARTable, for internal use */
    private class SMARTable {
        private static final String VINF = "VINF";

        HashMap<Long, Map<String, Set<String>>> tbl;

        SMARTable() {
            tbl = new HashMap<Long, Map<String, Set<String>>>();
        }

        void put(Long key, Map<String, Set<String>> value) {
            tbl.put(key, value);
        }

        Map<String, Set<String>> get(Long key) {
            return tbl.get(key);
        }

        void clear() {
            tbl.clear();
        }

        /**
         * Use symbolic value VINF to widen value-set
         * @param all
         * @param e
         */
        void widenVS(Set<String> final_set, Set<String> new_set ) {
            /* Already widened to VINF */
            if (final_set.contains("VINF")) return;

            final_set.addAll(new_set);
            /* do widening if it has more than 3 values */
            if (final_set.size() > 3) {
                String vs[] = final_set.toArray(new String[final_set.size()]);
                String pt[] = new String[vs.length - 1];

                for (int i = 1; i < vs.length; i++) {
                    pt[i-1] = symbolicSub(vs[i], vs[i-1]);
                }

                /* Equal difference series ? */
                boolean bSame = true;
                for (int i = 1; bSame && (i < pt.length); i++) {
                    bSame = (pt[i].equals(pt[i-1]));
                }

                /* Widening */
                if (bSame) {
                    System.out.println("335: add VINF");
                    final_set.add(new String(VINF));
                }
            }
        }

        /**
         * Test if all elements from ee
         * @param final_set
         * @param new_set
         * @return
         */
        boolean containVS(Set<String> final_set, Set<String> new_set ) {
            System.out.println("439: final_set: " + final_set.toString());
            System.out.println("440: new_set:" + new_set.toString());

            if (final_set.containsAll(new_set)) {
                System.out.println("404: true");
                return true;
            }
            else if (final_set.contains("VINF")) {
                System.out.println("408: true");
                return true;
            }
            else {
                System.out.println("412: false");
                return false;
            }
        }


        boolean containsAll(SMARTable from) {
            if (tbl.entrySet().containsAll(from.tbl.entrySet())) return true;

            /* test if is widened? */
            boolean bContain;
            Map<Long, Map<String, Set<String>>> fromLineTbl = from.tbl;
            for(Map.Entry<Long, Map<String, Set<String>>> e : fromLineTbl.entrySet()) {
                Long lineno = e.getKey();
                Map<String, Set<String>> smart = tbl.get(lineno);
                if (smart == null) return false;

                /* Test if all values exist */
                Map<String, Set<String>> fromVStbl = e.getValue();
                for (Map.Entry<String, Set<String>> ee: fromVStbl.entrySet()) {
                    String addr = ee.getKey();
                    Set<String> vs = smart.get(addr);
                    if (vs == null) continue;   // This instruction may access another element of an array: mov [rbp + rax], 0x10

                    bContain = containVS(vs, ee.getValue());

                    if (! bContain) return false;
                }
            }
            return true;
        }

        void putAll(SMARTable from) {
            Map<Long, Map<String, Set<String>>> fromLineTbl = from.tbl;
            for(Map.Entry<Long, Map<String, Set<String>>> e : fromLineTbl.entrySet()) {
                Long lineno = e.getKey();
                Map<String, Set<String>> smart = tbl.get(lineno);
                if (smart == null) {
                    tbl.put(lineno, e.getValue());
                    continue;
                }

                /* Test if all values exist */
                Map<String, Set<String>> fromVStbl = e.getValue();
                for (Map.Entry<String, Set<String>> ee: fromVStbl.entrySet()) {
                    String addr = ee.getKey();
                    Set<String> vs = smart.get(addr);
                    if (vs == null) {
                        smart.put(addr, ee.getValue());
                    }
                    else {
                        widenVS(vs, ee.getValue());
                    }
                }
            }
        }
    }

    /* Each basic block has its own SMARTable, used for storing memory access record*/
    SMARTable m_smarTable;
    SMARTable m_cycSMART;   // An SMARTable for traversing;

    /* CPU state */
    private class CPUState {
        Map<String, String> regs;
        Map<String, String> mems;


        CPUState deepCopy() {
            /* Create a new instance of CPUState */
            CPUState s = new CPUState();

            s.regs = deepCopyMAP(regs);
            s.mems = deepCopyMAP(mems);

            return s;
        }

        Map<String, String> deepCopyMAP(Map<String, String> from) {
            Map<String, String> to = new HashMap<String, String>();

            for(Map.Entry<String,String> e : from.entrySet()) {
                String k = new String(e.getKey());
                String v = new String(e.getValue());
                to.put(k, v);
            }
            return to;
        }
    }


    private Set<CPUState> m_CPUState;
    private CPUState m_curCPUState;


    private final OperandType OPRDTYPE;     // Used for testing operand types
    DecimalFormat m_digitFmt;               // Add a +/- sign before digit values


    private class UnspportInstruction extends RuntimeException {
        UnspportInstruction(String lineno, InstructionDB instr) {
            System.out.println(String.format("%s: %s, unsupported Instruction", lineno, instr.toString()));
        }
    }


    private class InvalidOperand extends RuntimeException {
        InvalidOperand(String lineno, InstructionDB instr, int operand_index) {
            /* print some details */
            System.out.println(String.format("%s: %s has inavlid operand", lineno, instr.toString()));
            for (Object o: instr.getOpObjects(operand_index)) {
                if (o instanceof String)
                    System.out.println((String)o);
                else if (o instanceof Character)
                    System.out.println((Character)o);
                else
                    System.out.println(o.getClass().getName());
            }
        }

        InvalidOperand(String lineno, Object [] objs) {
            /* print some details */
            System.out.println(String.format("%s: inavlid operand", lineno));
            for (Object o: objs) {
                if (o instanceof String)
                    System.out.println((String)o);
                else if (o instanceof Character)
                    System.out.println((Character)o);
                else
                    System.out.println(o.getClass().getName());
            }
        }
    }


    public BlockSMAR(HardwareArch arch, Program program, Listing listintDB, Function function, CodeBlock block) {
        m_arch = arch;
        m_program = program;
        m_listDB = listintDB;
        m_function = function;
        m_block = block;

        m_bVisted = false;
        m_CPUState = null;

        OPRDTYPE = m_arch.getOprdTester();

        /* Each basic block has its own SMARTable */
        m_smarTable = new SMARTable();
        m_dirtySMART = true;    // Set it do dirty at the first time

        m_digitFmt = new DecimalFormat("+#;-#");
    }


    public CodeBlock getCodeBlock() {
        return m_block;
    }


    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        return m_smarTable.tbl;
    }

    boolean isDirty() {
        return m_dirtySMART;
    }

    public int getNumOfCPUState() {
        if (m_CPUState == null)
            return 0;
        else
            return m_CPUState.size();
    }


    public void setNexts(Set<BlockSMAR> nexts) {
        m_nexts = nexts;
    }


    public void setCPUState(Map<String, String> register_status, Map<String, String> memory_status) {
        if (m_CPUState == null) {
            m_CPUState = new HashSet<CPUState>();
        }

        /* Create a new instance of CPUState */
        CPUState s = new CPUState();

        m_CPUState.add(s);
        s.regs = register_status;
        s.mems = memory_status;
    }

    /**
     * Fork a CPU state if needs
     * @param state
     * @param reuse
     */
    private void forkCPUState(CPUState state, boolean reuse) {
        if (m_CPUState == null) {
            m_CPUState = new HashSet<CPUState>();
        }

        if (reuse) {
            m_CPUState.add(state);
        }
        else {
            /* Create a new instance of CPUState */
            CPUState s = state.deepCopy();
            m_CPUState.add(s);
        }
    }


    public void runControlFlowOnce() {
        /* Recording memory access at the start of the current code block, in DFS order */
        Set<CPUState> selfloopCPUState;  // A block may loop itself. If yes, we store a copy of CPUState for it

        selfloopCPUState = null;
        m_bVisted = true;   // Current block is already visted, so no need to traverse again at current cycle */

        /* Set the CPU state for each successor */
        for (Iterator<CPUState> itor = m_CPUState.iterator(); itor.hasNext();) {
            CPUState cpuState = itor.next();
            m_curCPUState = cpuState;

            doRecording();

            /* Set the CPU state for each successor */
            int cntNxt = m_nexts.size();
            for (BlockSMAR nextBlk: m_nexts) {
                cntNxt--;

                /* self-loop ?*/
                if (nextBlk == this) {
                    /* If there is a self-loop, copy the CPU state for next traversing cycle */
                    if (selfloopCPUState == null) {
                        selfloopCPUState = new HashSet<CPUState>();
                    }
                    CPUState s = m_curCPUState.deepCopy();
                    selfloopCPUState.add(s);
                    continue;
                }

                /* fork register status if there are more than 2 successors */
                if (cntNxt > 0) {
                    nextBlk.forkCPUState(m_curCPUState, false);
                }
                else {
                    nextBlk.forkCPUState(m_curCPUState, true);
                }
            }

            /* use itor.remove() instead of Set.remove() */
            itor.remove();
        }

        /* All CPUState have been consumed */
        assert(m_CPUState.size() == 0);
        m_curCPUState = null;

        if (selfloopCPUState != null) {
            m_CPUState = selfloopCPUState;
        }

        /* traverse all outgoing edges in this block */
        for (BlockSMAR nextBlk: m_nexts) {
            if (!nextBlk.m_bVisted && nextBlk.m_dirtySMART) nextBlk.runControlFlowOnce();
        }
    }


    private String getRegValue(String register) {
        String reg, val;

        reg = m_arch.getRegisterFullname(register);
        val = m_curCPUState.regs.get(reg);

        return val;
    }


    private String getMemValue(String address) {
        return m_curCPUState.mems.get(address);
    }


    private void doRecording() {
        /* iterate every instruction in this block */
        AddressSet addrSet = m_block.intersect(m_function.getBody());
        InstructionIterator iiter = m_listDB.getInstructions(addrSet, true);

        if (m_cycSMART == null) m_cycSMART = new SMARTable();
        m_cycSMART.clear();

        while (iiter.hasNext()) {
            InstructionDB inst = (InstructionDB)iiter.next();
            int nOprand = inst.getNumOperands();

            try {
                if (nOprand == 0) {
                    _doRecording0(inst);
                }
                else if (nOprand == 1)  {
                    _doRecording1(inst);
                }
                else if (nOprand == 2)  {
                    _doRecording2(inst);
                }
                else if (nOprand == 3)  {
                    _doRecording3(inst);
                }
                else {
                    /* Throw exception */
                    throw new UnspportInstruction("483: %s ? oprands", inst);
                }
            }
            catch (Exception e) {
                if (e instanceof InvalidOperand) {

                }
                else if (e instanceof InvalidOperand) {

                }
                else {
                    System.out.println(String.format("485: %s err: %s", inst.toString(), e.toString()));
                }
            }
        }
        if (m_smarTable.containsAll(m_cycSMART)) {
            System.out.println("593: YES");
            m_dirtySMART = false;
        }
        else {
            m_smarTable.putAll(m_cycSMART);
            m_dirtySMART = true;
            System.out.println("598: False");
        }
    }


    private void _doRecording0(InstructionDB inst) {
        System.out.println("331: " + inst.toString());
        String op = inst.getMnemonicString();

        if(op.equalsIgnoreCase("nop")) {
            return;
        }

        else if(op.equalsIgnoreCase("cbw") || op.equalsIgnoreCase("cwde") || op.equalsIgnoreCase("cdqe")) {
            /* CBW/CWDE/CDQE: AX ← sign-extend of AL. */
            return;
        }


        else if(op.equalsIgnoreCase("ret")) {
            _record0ret(inst);
        }

        else if(op.equalsIgnoreCase("leave")) {
            _record0leave(inst);
        }

        else {
            throw new UnspportInstruction("333: 0 oprands", inst);
        }
    }


    private void _record0ret(InstructionDB inst) {
        /* pop rip */
        String strValue;
        /* Update RSP register status */
        strValue = getRegValue("RSP");
        strValue = symbolicAdd(strValue, 8);
        updateRegister(inst.getAddress().getOffset(), "RSP", strValue);
    }


    private void _record0leave(InstructionDB inst) {
        /* mov rsp, rbp; pop rbp */
        String strValSP, strValBP;
        String strValue;

        /* mov rsp, rbp */
        strValBP = getRegValue("RBP");
        updateRegister(inst.getAddress().getOffset(), "RSP", strValBP);

        /* pop rbp */
        strValSP = getRegValue("RSP");
        strValue = getMemValue(strValSP);
        updateRegister(inst.getAddress().getOffset(),  "RBP", strValue);

        /* Clean memory status */
        strValSP = getRegValue("RSP");
        m_curCPUState.mems.remove(strValSP);

        /* Update register RSP */
        strValSP = getRegValue("RSP");
        strValue = symbolicAdd(strValSP, 8);
        updateRegister(inst.getAddress().getOffset(), "RSP", strValue);
    }


    private void _doRecording1(InstructionDB inst) {
        System.out.println("340: " + inst.toString());

        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        String op = inst.getMnemonicString();

        if(op.equalsIgnoreCase("push")) {
            _record1push(inst);
        }

        else if (op.equalsIgnoreCase("pop")) {
            _record1pop(inst);
        }

        else if (op.equalsIgnoreCase("div")) {
            _record1div(inst);
        }

        else if (op.equalsIgnoreCase("nop")) {
            /* NOP [RAX + RAX*0x1] */
            return;
        }

        else if (op.equalsIgnoreCase("call")) {
            /* call xxx */
            System.out.println("400: fix-me, call xxx");
        }
        else if (op.charAt(0) == 'j' || op.charAt(0) == 'J' ) {
            /* jump xxx & jcc xx */
            System.out.println("405: fix-me, jxx");
        }
        else if (op.equalsIgnoreCase("ret")) {
            /* retn 0x8 */
            _record1retn(inst);
        }

        else {
            throw new UnspportInstruction("582: 1 oprands", inst);
        }
    }


    private void _record1push(InstructionDB inst) {
        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        /* push reg; push 0x1234; */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        /* Get oprand value & upadte MAR-table */
        if (OPRDTYPE.isRegister(oprdty)) { // register
            strValue = getRegValue(oprd);
        }
        else if (OPRDTYPE.isScalar(oprdty)){ // Constant value
            strValue = oprd;
        }
        else { // must be address: two memory oprand does't supported by x86 and ARM
            System.out.println("326: throw exception, Wrong operand");
        }

        /* Update MAR-table & register status */
        strAddr = getRegValue("RSP");
        strAddr = symbolicSub(strAddr, 8);
        updateRegister(inst.getAddress().getOffset(), "RSP", strAddr);

        /* Update MAR-table & memory status */
        strAddr = getRegValue("RSP");
        updateMemoryWriteAccess(inst.getAddress().getOffset(), strAddr, strValue);
    }

    private void _record1pop(InstructionDB inst) {
        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        /* pop reg */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        /* operand must be a reigster. Other type of memory access does't supported by x86 and ARM  */
        assert(OPRDTYPE.isRegister(oprdty));

        // strAddr = getRegValue("RSP");
        // updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr);

        /* Get value from stack && update rigister status */
        strValue = getRegValue("RSP");
        strValue = getMemValue(strValue);
        updateRegister(inst.getAddress().getOffset(), oprd, strValue);

        /* Clean memory status */
        strValue = getRegValue("RSP");
        m_curCPUState.mems.remove(strValue);

        /* Update RSP register status */
        strValue = getRegValue("RSP");
        strValue = symbolicAdd(strValue, 8);
        updateRegister(inst.getAddress().getOffset(), "RSP", strValue);
    }


    private void _record1div(InstructionDB inst) {
        /* DIV r/m8 */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        String strAddr, strValue;
        long iVal;

        Object [] objs;

        if (OPRDTYPE.isRegister(oprdty)) {
            /* sub reg, reg */
            oprd = inst.getDefaultOperandRepresentation(0);
            strValue = getRegValue(oprd);
        }
        else if (OPRDTYPE.isScalar(oprdty)){
            /* sub rsp, 8; */
            oprd = inst.getDefaultOperandRepresentation(0);
            strValue = oprd;
        }
        else {
            /* others */
            objs = inst.getOpObjects(0);

            strAddr = _getMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr);

            /* fetch the value from the memory elememt */
            strValue = getMemValue(strAddr);
        }

        String strDx, strAx, strQue, strRem;
        long iDx, iAx, iQue, iRem;

        strDx = getRegValue("RDX");
        strAx = getRegValue("RAX");

        if (isPureSymbolic(strDx) || isPureSymbolic(strAx)) {
            strDx = strDx.replaceAll("\\s+","");
            strAx = strAx.replaceAll("\\s+","");

            strQue = String.format("D(%s:%s/%s)", strDx, strAx, strValue);
            strRem = String.format("D(%s:%s%%%s)", strDx, strAx, strValue);
        }
        else {
            iDx = Long.decode(strDx);
            iAx = Long.decode(strAx);
            if (isPureSymbolic(strValue)) {
                strDx = strDx.replaceAll("\\s+","");
                strAx = strAx.replaceAll("\\s+","");

                strQue = String.format("D(%s:%s/%s)", strDx, strAx, strValue);
                strRem = String.format("D(%s:%s%%%s)", strDx, strAx, strValue);
            }
            else {
                iQue = (iDx * iAx) / Long.decode(strValue);
                iRem = (iDx * iAx) % Long.decode(strValue);
                strQue = String.valueOf(iQue);
                strRem = String.valueOf(iRem);
            }
        }

        /* upate register status */
        updateRegister(inst.getAddress().getOffset(), "RAX", strQue);
        updateRegister(inst.getAddress().getOffset(), "RDX", strRem);
    }


    private void _record1retn(InstructionDB inst) {
        String strValue,  strValSP, oprd;

        oprd = inst.getDefaultOperandRepresentation(0);

        /* Update RSP register status */
        strValSP = getRegValue("RSP");
        strValue = symbolicAdd(strValSP, Integer.decode(oprd) + 8);
        updateRegister(inst.getAddress().getOffset(), "RSP", strValue);
    }

    private void _doRecording2(InstructionDB inst) {
        System.out.println("414: " + inst.toString());

        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("add")) {
            /* sub reg, reg; sub reg, 0x1234; sub reg, mem; sub mem, reg; sub mem, 0x1234 */
            _record2addsub(inst, '+');
        }

        else if (op.equalsIgnoreCase("sub")) {
            _record2addsub(inst, '-');
        }

        else if (op.equalsIgnoreCase("mov")) {
            _record2mov(inst);
        }

        else if (op.equalsIgnoreCase("movss")) {
            _record2mov(inst);
        }

        else if (op.equalsIgnoreCase("movaps")) {
            _record2mov(inst);
        }

        else if (op.equalsIgnoreCase("movsx")) {
            /* MOVSX r, r/m */
            _record2mov(inst);
        }

        else if (op.equalsIgnoreCase("movsxd")) {
            /* movsxd r, r/m */
            _record2mov(inst);
        }

        else if (op.equalsIgnoreCase("lea")) {
            _record2lea(inst);
        }

        else if (op.equalsIgnoreCase("xor")) {
            _record2xor(inst);
        }

        else if (op.equalsIgnoreCase("test")) {
            _record2test(inst);
        }

        else if (op.equalsIgnoreCase("cmp")) {
            _record2test(inst);
        }

        else if (op.equalsIgnoreCase("shl")) {
            _record2shl(inst);
        }

        else if (op.equalsIgnoreCase("shr")) {
            _record2shr(inst);
        }

        else {
            throw new UnspportInstruction("689: 2 oprands", inst);
        }
    }

    private void _record2addsub(InstructionDB inst, char op) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        if (OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            strVal0 = getRegValue(oprd0);

            if (OPRDTYPE.isRegister(oprd1ty)) {
                /* sub reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);

                if (op == '+')
                    strValue = symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strValue = symbolicSub(strVal0, strVal1);
                else
                    strValue = strVal0; //fix-me

                updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                /* sub rsp, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                if (op == '+')
                    strValue = symbolicAdd(strVal0, Long.decode(oprd1));
                else if (op == '-')
                    strValue = symbolicSub(strVal0, Long.decode(oprd1));
                else
                    strValue = strVal0;

                /* upate register status */
                updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
            }
            else {
                /* others */
                objs = inst.getOpObjects(1);

                strAddr1 = _getMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemValue(strAddr1);


                if (op == '+')
                    strValue = symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strValue = symbolicSub(strVal0, strVal1);
                else
                    strValue = strVal0;

                /* upate register status */
                updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
            }
        }
        else {
            /* The first operand is in memory */
            /* Ghidra bug: sub [RAX],RDX -> _, ADDR|REG */
            if (OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            }
            else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand("773", inst, 1);
            }

            objs = inst.getOpObjects(0);
            strAddr0 = _getMemAddress(objs);

            /* fetch the value from the memory elememt */
            strVal0 = getMemValue(strAddr0);

            if (op == '+')
                strValue = symbolicAdd(strVal0, strVal1);
            else if (op == '-')
                strValue = symbolicSub(strVal0, strVal1);
            else
                strValue = strVal0;

            /* update memory write access */
            updateMemoryWriteAccess(inst.getAddress().getOffset(), strAddr0, strValue);
        }
    }


    private void _record2mov(InstructionDB inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
        if (OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            if (OPRDTYPE.isRegister(oprd1ty)) {
                /* mov reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                strVal1  = getRegValue(oprd1);
                updateRegister(inst.getAddress().getOffset(), oprd0, strVal1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                /* mov rax, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;

                /* upate register status */
                updateRegister(inst.getAddress().getOffset(), oprd0, strVal1);
            }
            else { /* memory oprand */
                objs = inst.getOpObjects(1);
                strAddr1 = _getMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemValue(strAddr1);

                /* upate register status */
                updateRegister(inst.getAddress().getOffset(), oprd0, strVal1);
            }
        }
        else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            if (OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = symbolicAdd("", oprd1);
            }
            else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand("858", inst, 1);
            }

            objs = inst.getOpObjects(0);

            strAddr0 = _getMemAddress(objs);

            /* update memory write access */
            updateMemoryWriteAccess(inst.getAddress().getOffset(), strAddr0, strVal1);
        }
    }


    private void _record2lea(InstructionDB inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* get the name of register */
        assert(OPRDTYPE.isRegister(oprd0ty));
        oprd0 = inst.getDefaultOperandRepresentation(0);

        /* get the value of second operand */
        objs = inst.getOpObjects(1);
        strAddr1 = _getMemAddress(objs);
        strValue = strAddr1;

        /* upate register status */
        updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
    }


    private void _record2xor(InstructionDB inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
        if (OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            strVal0  = getRegValue(oprd0);
            if (OPRDTYPE.isRegister(oprd1ty)) {
                /* xor reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                strVal1  = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                /* mov rax, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            }
            else { /* memory oprand */
                objs = inst.getOpObjects(1);
                strAddr1 = _getMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemValue(strAddr1);
            }

            /* upate register status */
            strValue = symbolicXor(strVal0, strVal1);
            updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
        }
        else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            if (OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            }
            else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand("949", inst, 1);
            }

            objs = inst.getOpObjects(0);

            strAddr0 = _getMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr0);

            /* fetch the value from the memory elememt */
            strVal0 = getMemValue(strAddr0);
            /* update memory write access */
            strValue = symbolicXor(strVal0, strVal1);

            updateMemoryWriteAccess(inst.getAddress().getOffset(), strAddr0, strValue);
        }
    }


    private void _record2test(InstructionDB inst) {
        /* test reg, reg; test reg, mem; test reg, 0x1234; test mem, reg; test mem, 0x1234 */
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* test oprand 0 */
        if (OPRDTYPE.isRegister(oprd0ty)) {
            /* do nothing */
        }
        else if (OPRDTYPE.isScalar(oprd0ty)){
            throw new InvalidOperand("987", inst, 0);
        }
        else {
            /* memory oprand */
            objs = inst.getOpObjects(0);
            strAddr0 = _getMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr0);
        }


        /* test oprand 1 */
        if (OPRDTYPE.isRegister(oprd1ty)) {
            /* do nothing */
        }
        else if (OPRDTYPE.isScalar(oprd1ty)){
            /* do nothing */
        }
        else {
            /* memory oprand */
            objs = inst.getOpObjects(1);
            strAddr1 = _getMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr1);
        }
    }

    private void _record2shl(InstructionDB inst) {
        /* shl rax, 0x4 */

        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* test oprand 0 */
        if (OPRDTYPE.isRegister(oprd0ty) && OPRDTYPE.isScalar(oprd1ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            oprd1 = inst.getDefaultOperandRepresentation(1);

            strVal0 = getRegValue(oprd0);
            iVal1 = Long.decode(oprd1);
            iVal1 = (long)Math.pow(2, iVal1);

            strValue = symbolicMul(strVal0, iVal1);

            /* upate register status */
            updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
        }
        else {
            throw new InvalidOperand("1061", inst, 0);
        }
    }

    private void _record2shr(InstructionDB inst) {
        /* shr rax, 0x4 */
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* test oprand 0 */
        if (OPRDTYPE.isRegister(oprd0ty) && OPRDTYPE.isScalar(oprd1ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            oprd1 = inst.getDefaultOperandRepresentation(1);

            strVal0 = getRegValue(oprd0);
            iVal1 = Long.decode(oprd1);
            iVal1 = (long)Math.pow(2, iVal1);

            strValue = symbolicDiv(strVal0, iVal1);

            /* upate register status */
            updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
        }
        else {
            throw new InvalidOperand("1092", inst, 0);
        }
    }


    private void _doRecording3(InstructionDB inst) {
        System.out.println("1035: " + inst.toString());

        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("imul")) {
            /* sub reg, reg; sub reg, 0x1234; sub reg, mem; sub mem, reg; sub mem, 0x1234 */
            _record3imul(inst);
        }
        else {
            throw new UnspportInstruction("1044: 3 oprands", inst);
        }
    }


    private void _record3imul(InstructionDB inst) {
        /* IMUL r16,r/m16,imm16 */
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        int oprd2ty = inst.getOperandType(2);

        String strVal0, strVal1, strVal2, strAddr0, strAddr1, strAddr2;
        String strValue, strAddress;
        String oprd0, oprd1, oprd2;
        long iVal0, iVal1, iVal2;

        Object[] objs;

        /* test oprand 0 */
        assert(OPRDTYPE.isRegister(oprd0ty) && OPRDTYPE.isScalar(oprd2ty));

        if (OPRDTYPE.isRegister(oprd1ty)) {
            oprd1 = inst.getDefaultOperandRepresentation(1);

            strVal1 = getRegValue(oprd1);
        }
        else if (OPRDTYPE.isScalar(oprd1ty)){
            throw new InvalidOperand("1069", inst, 1);
        }
        else {
            /* memory oprand */
            objs = inst.getOpObjects(1);
            strAddr1 = _getMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress().getOffset(), strAddr1);

            /* fetch the value from the memory elememt */
            strVal1 = getMemValue(strAddr1);
        }

        oprd2 = inst.getDefaultOperandRepresentation(2);
        iVal2 = Long.decode(oprd2);
        strValue = symbolicMul(strVal1, iVal2);

        /* upate register status */
        oprd0 = inst.getDefaultOperandRepresentation(0);
        updateRegister(inst.getAddress().getOffset(), oprd0, strValue);
    }


    private String _getMemAddress(Object[] objs_of_MemOperand) {
        /* A memory oprand from Ghidra, consits with an array of objects */
        Object[] objs = objs_of_MemOperand;
        String strValue, strAddress;

        if (objs.length == 1) {
            /* mov reg, [reg]; mov reg, [0x48000] */
            if (objs[0] instanceof Register) {
                Register r = (Register)objs[0];

                /* get regiser value */
                strValue = getRegValue(r.getName());
                return strValue;
            }
            else if (objs[0] instanceof Scalar) {
                Scalar s = (Scalar)objs[0];

                /* get memory address */
                strAddress = String.valueOf(s.getValue());
                return strAddress;

            }
            else if (objs[0] instanceof GenericAddress) {
                GenericAddress a = (GenericAddress)objs[0];

                strAddress = String.valueOf(a.getOffset());
                return strAddress;
            }

            else {
                /* This operand is invalid, throw exeception */
                throw new InvalidOperand("992", objs_of_MemOperand);
            }
        }
        else if (objs.length == 2) {
            /* Registet + Scaler: i.e [RBP + -0x28]
             * Registet + Scaler: [-0xf8 + RBP]
             */
            Register r;
            Scalar s;

            if ((objs[0] instanceof Register) && (objs[1] instanceof Scalar)) {
                r = (Register)objs[0];
                s = (Scalar)objs[1];
            }
            else if ((objs[0] instanceof Scalar) && (objs[1] instanceof Register)) {
                r = (Register)objs[1];
                s = (Scalar)objs[0];
            }
            else {
                throw new InvalidOperand("1019", objs_of_MemOperand);
            }

            strValue = getRegValue(r.getName());
            strAddress = symbolicAdd(strValue, s.getValue());

            return strAddress;
        }
        else if (objs.length == 3) {
            /* Registet + Register * Scaler: [RDX + RAX*0x1] */
            if ((objs[0] instanceof Register) && (objs[1] instanceof Register) && (objs[2] instanceof Scalar)) {
                Register rb, ri;
                Scalar s;
                String vb, vi;

                rb = (Register)objs[0];
                ri = (Register)objs[1];
                s = (Scalar)objs[2];

                System.out.println(String.format("%s + %s*%d?", rb.getName(), ri.getName(), s.getValue()));
                vb = getRegValue(rb.getName());
                vi = getRegValue(ri.getName());

                strValue = symbolicMul(vi, s.getValue());
                strAddress = symbolicAdd(vb, strValue);

                return strAddress;
            }
            else {
                throw new InvalidOperand("1319", objs_of_MemOperand);
            }
        }
        else if (objs.length == 4) {
            /* [RBP + RAX*0x4 + -0x60] */
            if ((objs[0] instanceof Register) && (objs[1] instanceof Register) &&
                    (objs[2] instanceof Scalar) && (objs[3] instanceof Scalar)) {
                Register rb, ri;
                Scalar sc, so;
                String vb, vi;

                rb = (Register)objs[0];
                ri = (Register)objs[1];
                sc = (Scalar)objs[2];
                so = (Scalar)objs[3];

                System.out.println(String.format("%s + %s*0x%x + 0x%x?", rb.getName(), ri.getName(), sc.getValue(), so.getValue()));
                vb = getRegValue(rb.getName());
                vi = getRegValue(ri.getName());

                strValue = symbolicMul(vi, sc.getValue());
                strAddress = symbolicAdd(vb, strValue);
                strAddress = symbolicAdd(strAddress, so.getValue());

                return strAddress;
                    }
            else {
                throw new InvalidOperand("1574", objs_of_MemOperand);
            }
        }
        else {
            /* This operand is invalid, throw exeception */
            throw new InvalidOperand("1579", objs_of_MemOperand);
        }
    }

    private boolean updateRegister(long line_no, String reg, String value) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;

        /* Update SMAR-table for Register reg */
        tmpMap = m_cycSMART.get(line_no);
        if (tmpMap == null) {
            tmpMap = new HashMap<String, Set<String>>();
            m_cycSMART.put(line_no, tmpMap);
        }

        reg = m_arch.getRegisterFullname(reg);
        tmpSet = tmpMap.get(reg);
        if (tmpSet == null) {
            tmpSet = new HashSet<String>();
            tmpMap.put(reg, tmpSet);
        }

        assert(tmpSet != null);
        tmpSet.add(value);

        /* for debugging */
        System.out.println(String.format("674: @0x%x: %s = %s", line_no, reg, value));

        /* Update register status */
        m_curCPUState.regs.put(reg, value);

        return true;
    }

    private boolean updateMemoryWriteAccess(long line_no, String address, String value) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;

        /* Update MAR-table for address */
        tmpMap = m_cycSMART.get(line_no);
        if (tmpMap == null) {
            tmpMap = new HashMap<String, Set<String>>();
            m_cycSMART.put(line_no, tmpMap);
        }

        tmpSet = tmpMap.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<String>();
            tmpMap.put(address, tmpSet);
        }

        assert(tmpSet != null);
        tmpSet.add(value);

        /* for debuging */
        System.out.println(String.format("686: @0x%x: [%s] = %s", line_no, address, value));

        /* Update memory status */
        m_curCPUState.mems.put(address, value);

        return true;
    }

    private boolean updateMemoryReadAccess(long line_no, String address) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;
        String value, symbol;

        value = m_curCPUState.mems.get(address);
        if (value == null) {
            /* This memory element is not yet been accessed, so creat a symbolic value */

            if (address.indexOf(' ') != -1) {
                symbol = String.format("V(%s)", address.replaceAll("\\s+",""));
            }
            else {
                symbol = "V" + address;
            }

            /* Update memory state */
            m_curCPUState.mems.put(address, symbol);
        }
        else {
            symbol = value;
        }

        /* Update MAR-table for memory read */
        tmpMap = m_cycSMART.get(line_no);
        if (tmpMap == null) {
            tmpMap = new HashMap<String, Set<String>>();
            m_cycSMART.put(line_no, tmpMap);
        }

        tmpSet = tmpMap.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<String>();
            tmpMap.put(address, tmpSet);

            tmpSet.add(symbol);     // Set a symbolic value
        }

        return true;
    }


}



interface HardwareArch {
    public String[] getAllRegisters();
    public String getRegisterFullname(String reg);
    public OperandType getOprdTester();
}


class LArchX86 implements HardwareArch {
    static final String [] m_Regs64 = {"RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};
    static final String [] m_Regs32 = {"EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D"};
    static final String [] m_Regs16 = {"AX", "BX", "CX", "DX", "DI", "SI", "BP", "SP"};
    static final String [] m_Regs8h = {"AH", "BH", "CH", "DH"};
    static final String [] m_Regs8l = {"AL", "BL", "CL", "DL"};
    static final String [] m_RegSeg = {"FS", "GS"};
    static final String [] m_RegXmm = {"XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7"};

    private Map<String, String> m_RegMap;
    private String[] m_AllRegs;

    private OperandType m_oprdTor;  // Use for testing opranad types

    LArchX86 () {
        m_RegMap = new HashMap<String, String>();

        int idx = 0;

        for (idx = 0; idx < m_RegSeg.length; idx++) {
            m_RegMap.put(m_RegSeg[idx], m_RegSeg[idx]);
        }

        for (idx = 0; idx < m_RegXmm.length; idx++) {
            m_RegMap.put(m_RegXmm[idx], m_RegXmm[idx]);
        }

        for (idx = 0; idx < m_Regs64.length; idx++) {
            m_RegMap.put(m_Regs64[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs32.length; idx++) {
            m_RegMap.put(m_Regs32[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs16.length; idx++) {
            m_RegMap.put(m_Regs16[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs8h.length; idx++) {
            m_RegMap.put(m_Regs8h[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs8l.length; idx++) {
            m_RegMap.put(m_Regs8l[idx], m_Regs64[idx]);
        }

        m_oprdTor = new OperandType();
    }


    public String[] getAllRegisters() {

        if (m_AllRegs == null) {
            String[] allRegs = new String[m_RegSeg.length + m_RegXmm.length + m_Regs64.length];

            System.arraycopy(m_RegSeg, 0, allRegs, 0, m_RegSeg.length);
            System.arraycopy(m_RegXmm, 0, allRegs, m_RegSeg.length, m_RegXmm.length);
            System.arraycopy(m_Regs64, 0, allRegs, m_RegSeg.length+m_RegXmm.length, m_Regs64.length);
            m_AllRegs = allRegs;
        }

        return m_AllRegs;
    }


    public String getRegisterFullname(String reg) {
        return m_RegMap.get(reg);
    }


    public OperandType getOprdTester() {
        return m_oprdTor;
    }
}



interface AnalysisPass {
    public boolean doAnalysis();
}


class ArrayAnalysis implements AnalysisPass {
    Map<Long, Map<String, Set<String>>> m_smart;

    ArrayAnalysis (Map<Long, Map<String, Set<String>>> smart) {
        m_smart = smart;
    }

    public boolean doAnalysis() {
        return true;
    }

}

class StructAnalysis implements AnalysisPass {
    Map<Long, Map<String, Set<String>>> m_smart;
    StructAnalysis (Map<Long, Map<String, Set<String>>> smart) {
        m_smart = smart;
    }

    public boolean doAnalysis() {
        return true;
    }


}


class ClassAnalysis implements AnalysisPass {
    Map<Long, Map<String, Set<String>>> m_smart;
    ClassAnalysis (Map<Long, Map<String, Set<String>>> smart) {

    }

    public boolean doAnalysis() {
        return true;
    }

}

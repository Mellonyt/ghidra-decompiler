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

        FunctionIterator iter = listing.getFunctions(true);
        FunctionSMAR smar;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            long fentry = f.getEntryPoint().getOffset();

            // Entry-point
            if (fentry != 0x04026a6)
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

        m_blocks = new HashMap<Address, BlockSMAR>();       // Basic Blocks of this function

        m_registers = new HashMap<String, String>();        // CPU State : Registers
        m_memories = new HashMap<String, String>();         // CPU State : Memory slot

        constructCFG();
    }

    private void InitMachineStatus() {
        /* Set register values to symbolic initial values */
        String[] allRegs = m_arch.getAllRegisters();

        for (String reg: allRegs) {
            m_registers.put(reg, "V" + reg);
        }

        /* Doesn't need to initialize memory state */
    }

    private void constructCFG() {
        /* Create BlockSMAR for each codeblock */
        AddressSetView addrSV = m_function.getBody();
        CodeBlockModel blkModel = new BasicBlockModel(m_program);

        try {
            CodeBlockIterator codeblkIt = blkModel.getCodeBlocksContaining(addrSV, m_monitor);
            while (codeblkIt.hasNext()) {
                CodeBlock codeBlk = codeblkIt.next();
                BlockSMAR smarBlk = new BlockSMAR(m_arch, m_program, m_listDB, m_function, codeBlk);
                Address addrStart = codeBlk.getFirstStartAddress();
                m_blocks.put(addrStart, smarBlk);
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to get basic blocks");
        }

        /* Initialize control-flow graph */
        try {
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
            System.err.println("Failed to contruct the CFG");
        }

    }

    /* The invariant here is that if a new CPU state exists, then it means something has changed since the last CPU state */
    public boolean doRecording() {
        CodeBlockModel blkModel = new BasicBlockModel(m_program);
        Address addr = m_function.getEntryPoint();
        CodeBlock firstBlk;

        try {
            firstBlk = blkModel.getCodeBlockAt(addr, m_monitor);
        }
        catch (Exception e) {
            System.out.println("210: Get first block failed");
            return false;
        }

        // Obtain the wrapper object for GHIDRA's basic block
        BlockSMAR smarBlk = m_blocks.get(firstBlk.getFirstStartAddress());
        smarBlk.setCPUState(m_registers, m_memories);

        try {
            InitMachineStatus();

            // Should be a loop, if any symbolic state for any block has changed in the last round
            int nExecutedBlks = 0;

            while (true) {
                /* Test if there are blocks have CPUstate to run? */
                smarBlk = null;
                for (BlockSMAR blk: m_blocks.values()) {
                    int nState = blk.getNumOfCPUState();
                    if (nState > 0) {
                        smarBlk = blk;
                        break;
                    }
                }

                if (smarBlk == null)  break;

                /* smarBlk != null */
                System.out.println("210: Start traversing");

                int nBlks = traverseBlocksOnce(smarBlk);
                if (nBlks == nExecutedBlks) {
                    /* there is a loop */
                    System.out.println("233: There is a loop?");
                }
                nExecutedBlks = nBlks;
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.out.println("255: Failed to traversBlocks");
        }
        return true;
    }


    private int traverseBlocksOnce(BlockSMAR start_block) {
        /* traverse all code-blocks recusively in depth-first search (DFS) order */
        for (BlockSMAR blk: m_blocks.values()) {
            blk.m_bVisted = false;
        }

        int nExecutedBlks;

        nExecutedBlks = start_block.runControlFlowOnce();
        return nExecutedBlks;
    }


    Map<Long, Map<String, Set<String>>> getSMARTable() {
        if (m_SMARTable == null) {
            m_SMARTable = new HashMap<Long, Map<String, Set<String>>>();   // Symbolic Store
            Map<Long, Map<String, Set<String>>> smart;

            for (BlockSMAR blk: m_blocks.values()) {
                smart = blk.getSMARTable();

                if (smart != null) m_SMARTable.putAll(smart);
            }
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
    public Boolean m_bVisted;           // Visted in current cycle

    /* Each basic block has its own SMARTable, used for storing memory access record*/
    Map<Long, Map<String, Set<String>>> m_smarTable;

    /* CPU state */
    private class CPUState {
        Map<String, String> regs;
        Map<String, String> mems;


        public CPUState deepCopy() {
                /* Create a new instance of CPUState */
                CPUState s = new CPUState();
    
                s.regs = deepCopyMAP(regs);
                s.mems = deepCopyMAP(mems);

                return s;
        }

        private Map<String, String> deepCopyMAP(Map<String, String> from) {
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
        m_smarTable = new HashMap<Long, Map<String, Set<String>>>();

        m_digitFmt = new DecimalFormat("+#;-#");
    }


    public CodeBlock getCodeBlock() {
        return m_block;
    }


    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        return m_smarTable;
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

    private void setCPUState(CPUState state, Boolean reuse) {
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


    /* traverse all code-blocks recusively in DFS order */
    public int runControlFlowOnce() {
        /* Recording the state of the symbolic memory store at the start of the current code block */

        /* Current block is already visted, no need to travers at current cycle */
        int nExcutedBlks = 1;

        m_bVisted = true;

        /* traverse all incoming edges into this block */
        for (Iterator<CPUState> itor = m_CPUState.iterator(); itor.hasNext();) {
            CPUState cpuState = itor.next();
            m_curCPUState = cpuState;

            //is (new_memacc_table != existing_access_table) set_dirty (curr_bb);
            doRecording();

            /* traverse all outgoing edges in this block */
            int cntNxt = m_nexts.size();
            for (BlockSMAR nextBlk: m_nexts) {
                cntNxt--;

                if (nextBlk.m_bVisted) {
                    /* traverse the next block in next cycle */
                    nextBlk.setCPUState(cpuState, false);
                    continue;
                }

                /* fork register status if needs */
                if (cntNxt > 0) {
                    nextBlk.setCPUState(cpuState, false);
                }
                else {
                    nextBlk.setCPUState(cpuState, true);
                }

                /* traverse next block */
                nExcutedBlks += nextBlk.runControlFlowOnce();
            }

            /* use itor.remove() instead of Set.remove() */
            itor.remove();
        }

        /* All CPUState have been consumed */
        m_curCPUState = null;

        return nExcutedBlks;
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
    }


    private void _doRecording0(InstructionDB inst) {
        System.out.println("331: " + inst.toString());
        String op = inst.getMnemonicString();

        if(op.equalsIgnoreCase("nop")) {
            return;
        }

        if(op.equalsIgnoreCase("ret")) {
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
                strVal1 = oprd1;
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
        else {
            /* This operand is invalid, throw exeception */
            throw new InvalidOperand("1330", objs_of_MemOperand);
        }
    }

    private boolean updateRegister(long line_no, String reg, String value) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;

        /* Update SMAR-table for Register reg */
        tmpMap = m_smarTable.get(line_no);
        if (tmpMap == null) {
            tmpMap = new HashMap<String, Set<String>>();
            m_smarTable.put(line_no, tmpMap);
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
        tmpMap = m_smarTable.get(line_no);
        if (tmpMap == null) {
            tmpMap = new HashMap<String, Set<String>>();
            m_smarTable.put(line_no, tmpMap);
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
        tmpMap = m_smarTable.get(line_no);
        if (tmpMap == null) {
            tmpMap = new HashMap<String, Set<String>>();
            m_smarTable.put(line_no, tmpMap);
        }

        tmpSet = tmpMap.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<String>();
            tmpMap.put(address, tmpSet);

            tmpSet.add(symbol);     // Set a symbolic value
        }

        return true;
    }


    private String symbolicAdd(String symbol0, String symbol1) {
        return _symbolicBinaryOP(symbol0, '+', symbol1);
    }


    private String symbolicSub(String symbol0, String symbol1) {
        return _symbolicBinaryOP(symbol0, '-', symbol1);
    }


    private String symbolicMul(String symbol0, String symbol1) {
        return _symbolicBinaryOP(symbol0, '*', symbol1);
    }


    private String symbolicDiv(String symbol0, String symbol1) {
        return _symbolicBinaryOP(symbol0, '/', symbol1);
    }


    private String _symbolicBinaryOP(String symbol0, char op, String symbol1) {
        /* parse the symbolic value symbol0 */
        String[] elems0 = symbol0.split("\\s", 0);
        String part0S;      // Symbolic part in symbol0
        long part0V;        // Value part in symbol0

        if (elems0.length == 1) {
            if (elems0[0].charAt(0) != 'V' && elems0[0].charAt(0) != 'D') {
                part0S = "";
                part0V = Long.decode(elems0[0]);
            }
            else {
                part0S = elems0[0];
                part0V = 0;
            }
        }
        else if (elems0.length == 2) {
            part0S = elems0[0];
            part0V = Long.decode(elems0[1]);
        }
        else {
            /* Throw exception */
            Object[] objs = {symbol0};
            throw new InvalidOperand("1448", objs);
        }

        /* parse the symbolic value symbol1 */
        String[] elems1 = symbol1.split("\\s", 0);
        String part1S;    // Symbolic part in symbol0
        long part1V;         // Value part in symbol0

        if (elems1.length == 1) {
            if (elems1[0].charAt(0) != 'V' && elems1[0].charAt(0) != 'D') {
                part1S = "";
                part1V = Long.decode(elems1[0]);
            }
            else {
                part1S = elems1[0];
                part1V = 0;
            }
        }
        else if (elems1.length == 2) {
            part1S = elems1[0];
            part1V = Long.decode(elems1[1]);
        }
        else {
            /* Throw exception */
            Object[] objs = {symbol1};
            throw new InvalidOperand("1578", objs);
        }

        /* calculate the result */
        String tmpS, newSymbol;
        long tmpV;

        if (op == '+' || op == '-' ) {
            tmpS = binaryOP(part0S, op, part1S);
            tmpV = binaryOP(part0V, op,  part1V);
            newSymbol = binaryOP(tmpS, '+', tmpV);
        }
        else if (op == '*') {
            if (part0S == "" || part1S == "") {
                tmpS = part0S + part1S;
                if (part0S == "") {
                    tmpS = binaryOP(tmpS, '*', part0V);
                }
                else {
                    tmpS = binaryOP(tmpS, '*', part1V);
                }
                tmpV = binaryOP(part0V, '*', part1V);

                newSymbol = binaryOP(tmpS, '+', tmpV);
            }
            else {
                String tmpL, tmpR;
                tmpS = binaryOP(part0S, '*', part1S);
                tmpL = binaryOP(part0S, '*', part1V);
                tmpR = binaryOP(part1S, '*', part0V);
                tmpV = binaryOP(part0V, '*', part1V);

                newSymbol = binaryOP(tmpS, '+', tmpL);
                newSymbol = binaryOP(newSymbol, '+', tmpR);
                newSymbol = binaryOP(newSymbol, '+', tmpV);
            }
        }
        else if (op == '/') {
            if (symbol0 == symbol1) {
                newSymbol = "1";
            }
            else if (part0S == "" && part1S == "") {
                tmpV = binaryOP(part0V, '/', part1V);
                newSymbol = binaryOP("", '+', tmpV);
            }
            else {
                newSymbol = String.format("D(%s%s/%s%s)", part0S, m_digitFmt.format(part0V), part1S, m_digitFmt.format((part1V)));
            }
        }
        else {
            /* Thow exception */
            Object[] objs = {"Unexpected operand"};
            throw new InvalidOperand("1559", objs);
        }

        return newSymbol;
    }


    private String symbolicAdd(String symbol, long value) {
        return _symbolicBinaryOP(symbol, '+', value);
    }


    private String symbolicSub(String symbol, long value) {
        return _symbolicBinaryOP(symbol, '-', value);
    }


    private String symbolicMul(String symbol, long value) {
        return _symbolicBinaryOP(symbol, '*', value);
    }


    private String symbolicDiv(String symbol, long value) {
        return _symbolicBinaryOP(symbol, '/', value);
    }


    /* Binary operation */
    private String _symbolicBinaryOP(String symbol, char op, long value) {
        /* parse the symbolic value */
        String[] elems = symbol.split("\\s", 0);
        String partS;       // symbolic part of symbol
        long partV;         // Numeric part of symbol

        if (elems.length == 1) {
            if (elems[0].charAt(0) != 'V' && elems[0].charAt(0) != 'D') {
                partS = "";
                partV = Long.decode(elems[0]);
            }
            else {
                partS = elems[0];
                partV = 0;
            }
        }
        else if (elems.length == 2) {
            partS = elems[0];
            partV = Long.decode(elems[1]);
        }
        else {
            /* Throw exception */
            String exp = String.format("%s %c 0x%x", symbol, op, value);
            Object[] objs = {exp};
            throw new InvalidOperand("1611", objs);
        }

        String newSymbol;
        long newValue;

        if (partS == "") {
            newValue = binaryOP(partV, op, value);
            newSymbol = binaryOP("", '+', newValue);
        }
        else if (partV == 0) {
            newSymbol = binaryOP(partS, op, value);
        }
        else {
            if (op == '+' || op == '-') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, '+', newValue);
            }
            else if (op == '*' || op == '/') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, op, value);
                newSymbol = binaryOP(newSymbol, '+', newValue);
            }
            else {
                /* Thow exception */
                Object[] objs = {"Unexpected operand", symbol, op};
                throw new InvalidOperand("1637", objs);
            }
        }

        return newSymbol;
    }


    private Boolean isPureSymbolic(String symbol) {
        /* Pure symbolic value: [V|D]xxx | 0 | _ */
        return ((symbol == "") || (symbol.charAt(0) == 'V') || (symbol.charAt(0) == 'D'));
    }


    /* generate new symbolic value */
    private String binaryOP(String pure_symbol0, char op, String pure_symbol1) {
        assert(pure_symbol0 == "" || pure_symbol0 == "0" || pure_symbol0.charAt(0) == 'V' || pure_symbol0.charAt(0) == 'D');
        assert(pure_symbol1 == "" || pure_symbol1 == "0" || pure_symbol1.charAt(0) == 'V' || pure_symbol1.charAt(0) == 'D');

        String newSymbol;
        long newValue;

        if (pure_symbol0 == "0") pure_symbol0 = "";
        if (pure_symbol1 == "0") pure_symbol1 = "";

        if (op == '+') {
            if (pure_symbol0 == "" || pure_symbol1 == "" ) {
                newSymbol = pure_symbol0 + pure_symbol1;
            }
            else if (("-" + pure_symbol0) == pure_symbol1 || pure_symbol0 == ("-" + pure_symbol1))  {
                newSymbol = "0";
            }
            else {
                newSymbol = String.format("D(%s+%s)", pure_symbol0, pure_symbol1);
            }
        }
        else if (op == '-')  {
            if (pure_symbol0 == pure_symbol1) {
                newSymbol = "0";
            }
            else if (pure_symbol0 == "") {
                newSymbol = String.format("-%s", pure_symbol1);
            }
            else if (pure_symbol1 == "" ) {
                newSymbol = pure_symbol0;
            }
            else {
                newSymbol = String.format("D(%s-%s)", pure_symbol0, pure_symbol1);
            }
        }
        else if (op == '*')  {
            if (pure_symbol0 == "" || pure_symbol1 == "" ) {
                newSymbol = "0";
            }
            else {
                newSymbol = String.format("D(%s*%s)", pure_symbol0, pure_symbol1);
            }
        }
        else if (op == '/')  {
            if (pure_symbol0 == pure_symbol1) {
                newSymbol = "1";
            }
            else if (pure_symbol0 == "") {
                newSymbol = "0";
            }
            else if (pure_symbol1 == "" ) {
                Object[] objs = {"Invalid operand"};
                throw new InvalidOperand("1359", objs);
            }
            else {
                newSymbol = String.format("D(%s/%s)", pure_symbol0, pure_symbol1);
            }
        }
        else {
            Object[] objs = {"Unexpected operation"};
            throw new InvalidOperand("1711", objs);
        }

        return newSymbol;
    }


    /* generate new symbolic value */
    private String binaryOP(String pure_symbol, char op, long value) {
        /* Binary operation for one pure-symbolic value and one long value:
         * VRSP + 0x8; VRSP - 0x8; VRSP * 0x8; VRSP / 0x8;
         */
        assert(pure_symbol == "" || pure_symbol == "0" || pure_symbol.charAt(0) == 'V' || pure_symbol.charAt(0) == 'D');

        String newSymbol;
        long newValue;

        if (pure_symbol == "0") pure_symbol = "";

        if (pure_symbol == "") {
            if (op == '+') {
                newValue = value;
            }
            else if (op == '-')  {
                newValue = 0 - value;
            }
            else if (op == '*')  {
                newValue = 0;
            }
            else if (op == '/')  {
                newValue = 0;
            }
            else {
                Object[] objs = {"Unexpected operation"};
                throw new InvalidOperand("1560", objs);
            }

            newSymbol = String.format("%s", m_digitFmt.format(newValue));
        }
        else if (value == 0) {
            if (op == '+') {
                newSymbol = pure_symbol;
            }
            else if (op == '-')  {
                newSymbol = pure_symbol;
            }
            else if (op == '*')  {
                newSymbol = "0";
            }
            else {
                Object[] objs = {"Unexpected operation"};
                throw new InvalidOperand("1577", objs);
            }
        }
        else {
            if (op == '+') {
                newValue = value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            }
            else if (op == '-')  {
                newValue = 0 - value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            }
            else if (op == '*')  {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                }
                else {
                    newSymbol = String.format("D(%s*%s)", pure_symbol, m_digitFmt.format(newValue));
                }
            }
            else if (op == '/')  {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                }
                else {
                    newSymbol = String.format("D(%s/%s)", pure_symbol, m_digitFmt.format(newValue));
                }
            }
            else {
                Object[] objs = {"Unexpected operation"};
                throw new InvalidOperand("1799", objs);
            }
        }

        return newSymbol;
    }



    private long binaryOP(long value0, char op, long value1) {
        /* Binary operation for two long values:
         * 0x12 + 0x34; 0x12 - 0x34; 0x12 * 0x34; 0x12 / 0x34;
         */
        long res;

        if (op == '+') {
            res = value0 + value1;
        }
        else if (op == '-') {
            res = value0 - value1;
        }
        else if (op == '*') {
            res = value0 * value1;
        }
        else if (op == '/') {
            res = value0 / value1;
        }
        else {
            /* Thow exception */
            Object[] objs = {"Unexpected operand"};
            throw new InvalidOperand("1350", objs);
        }
        return res;
    }


    private String symbolicXor(String symbol0, String symbol1) {
        String val0 = symbol0.strip();
        String val1 = symbol1.strip();
        String value;

        if (val0 == val1) {
            value = "0";
        }
        else {
            value = String.format("D(%s^%s)", val0.replaceAll("\\s+",""), val1.replaceAll("\\s+",""));
            System.out.println("D" + value);
        }

        return value;
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

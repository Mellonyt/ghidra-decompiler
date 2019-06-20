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

    

    /* Each basic block has its own SMARTable, used for storing memory access record*/
    SMARTable m_smarTable;
    SMARTable m_cycSMART;   // An SMARTable for traversing;



    private Set<CPUState> m_CPUState;
    private CPUState m_curCPUState;


    private final OperandType OPRDTYPE;     // Used for testing operand types
    DecimalFormat m_digitFmt;               // Add a +/- sign before digit values


    


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

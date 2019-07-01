package symbolicVSA;

import symbolicVSA.MachineState;
import symbolicVSA.SMARTable;
import symbolicVSA.X86Interpreter;

/*
   Function-level symbolic memory access recording (SMAR)
   Every symbolic value defines a domain
   */
public class FunctionSMAR {
    private final Program m_program;
    private final Listing m_listDB;
    private final Function m_function;
    private TaskMonitor m_monitor;

    private Map<Address, ExecutionBlock> m_blocks; // All blocks in this function

    public FunctionSMAR(Program program, Listing listintDB, Function function, TaskMonitor monitor) {
        m_program = program;
        m_listDB = listintDB;
        m_function = function;
        m_monitor = monitor;

        constructCFG();
    }

    /**
     * Construct the CFG for all basic blocks
     */
    private void constructCFG() {
        if (m_blocks == null)
            m_blocks = new HashMap<>(); // Basic Blocks of this function

        try {
            /* Create ExecutionBlock for each Ghidra's codeblock */
            CodeBlockModel blkModel = new BasicBlockModel(m_program);
            AddressSetView addrSV = m_function.getBody();
            CodeBlockIterator codeblkIt = blkModel.getCodeBlocksContaining(addrSV, m_monitor);

            while (codeblkIt.hasNext()) {
                CodeBlock codeBlk = codeblkIt.next();
                ExecutionBlock smarBlk = new ExecutionBlock(m_listDB, m_function, codeBlk);
                Address addrStart = codeBlk.getFirstStartAddress();
                m_blocks.put(addrStart, smarBlk);
            }
        } catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to obtain Ghidra's basic blocks @ " + m_function.getName());
        }

        try {
            /* Create control-flow graph */
            for (ExecutionBlock curSMARBlk : m_blocks.values()) {
                /* find the next-blocks of current code-block */
                Set<ExecutionBlock> nxtSMARblks = new HashSet<>();
                CodeBlock curCodeBlk = curSMARBlk.getCodeBlock();
                CodeBlockReferenceIterator di = curCodeBlk.getDestinations(m_monitor);
                while (di.hasNext()) {
                    CodeBlockReference ref = di.next();
                    CodeBlock nxtCodeBlk = ref.getDestinationBlock();
                    Address addrStart = nxtCodeBlk.getFirstStartAddress();
                    ExecutionBlock nxtSMARBlk = m_blocks.get(addrStart);
                    if (nxtSMARBlk != null) {
                        nxtSMARblks.add(nxtSMARBlk);
                    }
                }

                /* set the m_next filed of current SMARTblock */
                curSMARBlk.setSuccessor(nxtSMARblks);
            }
        } catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to contruct the CFG for function " + m_function.getName());
        }
    }

    /**
     * Do symbolic memory access recording for current function. Apply the VSA
     * algorithm.
     * 
     * @return
     */
    public boolean doSMARecording() {
        /* Obtain the wrapper object for GHIDRA's basic block */
        Address fentry = m_function.getEntryPoint();
        ExecutionBlock firstBlk = m_blocks.get(fentry);
        if (firstBlk == null) {
            throw new NullPointerException("Cannot get the first block");
        }

        /* Initialize the Machine state */
        X86Interpreter inpt = X86Interpreter.getInterpreter();
        MachineState init_state = MachineState.createInitState(inpt.getCPU());
        firstBlk.setInitMachState(init_state);

        try {
            /* loop until no changes to symbolic state */
            ExecutionBlock smarBlk;
            while (true) {
                /* pick up a block which has Machine-state to run? */
                smarBlk = null;
                for (ExecutionBlock blk : m_blocks.values()) {
                    int nState = blk.getNumOfMachState();
                    boolean bDirty = blk.isSMRTDirty();

                    if (nState > 0 && bDirty) {
                        smarBlk = blk;
                        break;
                    }
                }

                /* end loop 8 */
                if (smarBlk == null)
                    break;

                /* smarBlk != null */
                traverseBlocksOnce(smarBlk);
            }
        } catch (Exception e) {
            /* fixe-me: ignore current function */
            System.out.println("272: Failed to traversBlocks: " + e.toString());
        }
        return true;
    }

    /**
     * traverse all code-blocks recusively in depth-first search (DFS) order
     * 
     * @param start_block: The block for starting traversing
     * @return
     */
    private boolean traverseBlocksOnce(ExecutionBlock start_block) {
        /* set all blocks un-visted */
        for (ExecutionBlock blk : m_blocks.values()) {
            blk.m_bVisted = false;
        }

        start_block.runCFGOnce();
        return true;
    }

    /**
     * Fetch SMART from each SMARBlock.
     * 
     * @return : the SMAR-table
     */
    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        SMARTable SMARTable = new SMARTable(); // Symbolic Store

        /* fetch SMART from each block */
        Map<Long, Map<String, Set<String>>> smart;

        for (ExecutionBlock blk : m_blocks.values()) {
            smart = blk.getSMARTable();

            if (smart != null)
                SMARTable.putAll(smart);
        }
        return SMARTable.m_tbl;
    }
}

/*
 * Basic block Representation for a given function, a wrapper of Ghidra's basic
 * block
 */
class SMARBlock {
    private Listing m_listDB;
    private CodeBlock m_block; // Ghidra's basic block

    private AddressSet m_addrSet; // The address space convering this block

    public boolean m_dirtySMART; // The SMRT table is diry, means current block needs a new round of recording if
                                 // also have MachineState

    X86Interpreter m_inpt;

    /*
     * Each basic block has its own SMARTable, used for storing memory access record
     */
    SMARTable m_smarTable;

    public SMARBlock(Listing listintDB, CodeBlock ghidra_block, AddressSet addrSet) {

        m_listDB = listintDB;
        m_block = ghidra_block;
        m_addrSet = addrSet;

        m_dirtySMART = true; // Set it do dirty at the first time

        m_inpt = X86Interpreter.getInterpreter();

        /* Each basic block has its own SMARTable */
        m_smarTable = new SMARTable();
    }

    public CodeBlock getCodeBlock() {
        return m_block;
    }

    boolean isDirty() {
        return m_dirtySMART;
    }

    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        return m_smarTable.m_tbl;
    }

    public void doRecording(MachineState state) {
        /* iterate every instruction in this block */
        InstructionIterator iiter = m_listDB.getInstructions(m_addrSet, true);
        SMARTable smart = new SMARTable();

        while (iiter.hasNext()) {
            Instruction inst = iiter.next();
            boolean suc = m_inpt.doRecording(state, smart, inst);
        }

        if (m_smarTable.containsAll(smart)) {
            m_dirtySMART = false;
        } else {
            m_smarTable.putAll(smart);
            m_dirtySMART = true;
        }
    }
}

class ExecutionBlock {
    private SMARBlock m_block;
    ExecutionBlock m_truecondBranch; // For conditional jumps, this node would be the jump target.
    ExecutionBlock m_falldownBranch;
    Set<ExecutionBlock> m_successor; // A set of successors

    private Set<MachineState> m_MachState;

    public boolean m_bVisted; // Visted in current cycle

    ExecutionBlock(Listing listintDB, Function function, CodeBlock ghidra_block) {
        AddressSet addrSet = ghidra_block.intersect(function.getBody());

        m_block = new SMARBlock(listintDB, ghidra_block, addrSet);
        m_MachState = new HashSet<>();
        m_bVisted = false;
    }

    public void setSuccessor(Set<ExecutionBlock> succsor) {
        m_successor = succsor;
    }

    public void setInitMachState(MachineState init_state) {
        if (m_MachState == null) {
            m_MachState = new HashSet<>();
        }

        m_MachState.add(init_state);
    }

    private void addMachState(MachineState new_state) {
        m_MachState.add(new_state);
    }

    public int getNumOfMachState() {
        if (m_MachState == null)
            return 0;
        else
            return m_MachState.size();
    }

    public CodeBlock getCodeBlock() {
        return m_block.getCodeBlock();
    }

    public boolean isSMRTDirty() {
        return m_block.isDirty();
    }

    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        return m_block.getSMARTable();
    }

    public void runCFGOnce() {
        /*
         * Recording memory access at the start of the current code block, in DFS order
         */
        Set<MachineState> selfloopMachState = null; // A block may loop itself. If yes, we store a copy of MachineState
                                                    // for it

        m_bVisted = true; // Current block is already visted, so no need to traverse again at current
                          // cycle */

        /* Set the CPU state for each successor */
        for (Iterator<MachineState> itor = m_MachState.iterator(); itor.hasNext();) {
            MachineState mstate = itor.next();

            m_block.doRecording(mstate);

            /* Set the CPU state for each successor */
            int cntNxt = m_successor.size();
            for (ExecutionBlock nextBlk : m_successor) {
                cntNxt--;

                /* self-loop ? */
                if (nextBlk == this) {
                    /* If there is a self-loop, copy the CPU state for next traversing cycle */
                    if (selfloopMachState == null) {
                        selfloopMachState = new HashSet<>();
                    }
                    MachineState s = mstate.forkState();
                    selfloopMachState.add(s);
                    continue;
                }

                /* fork register status if there are more than 2 successors */
                if (cntNxt > 0) {
                    MachineState s = mstate.forkState();
                    nextBlk.addMachState(s);
                } else {
                    nextBlk.addMachState(mstate);
                }
            }

            /* use itor.remove() instead of Set.remove() */
            itor.remove();
        }

        /* All MachineState have been consumed */
        if (m_MachState.size() != 0) {
            throw new NullPointerException("Invalid machine state");
        }

        if (selfloopMachState != null) {
            m_MachState = selfloopMachState;
        }

        /* traverse all outgoing edges in this block */
        for (ExecutionBlock nextBlk : m_successor) {
            if (!nextBlk.m_bVisted && nextBlk.isSMRTDirty())
                nextBlk.runCFGOnce();
        }
    }

}
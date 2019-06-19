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


import ghidra.app.script.GhidraScript;

import ghidra.program.model.listing.*;
import ghidra.program.model.address.AddressSetView;

import ghidra.program.database.function.*;
import ghidra.program.database.code.InstructionDB;

import ghidra.program.model.lang.OperandType;

public class VSA extends GhidraScript {
    Program program;
    Listing listing;

    @Override
    public void run() {
        program = state.getCurrentProgram();
        listing = program.getListing();

        FunctionIterator iter = listing.getFunctions(true);
        FunctionVSA vsa;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            long fentry = f.getEntryPoint().getOffset();

            // Entry-point
            if (fentry != 0x0401d92) // _ZN6Animal9printInfoEv
                continue;

            println("Function Entry: " + f.getEntryPoint());
            println("Function Name: " + f.getName());

            vsa = new FunctionVSA(program, listing, f, monitor);
            vsa.doInterpration();
        }
    }
}


class FunctionVSA {
    Program m_program;
    Listing m_listDB;
    FuntionDB m_function;
    TaskMonitor m_monitor;

    Map<String, String> m_registers;  // Track the register status
    Map<String, Set> m_VSATble;       // The function-level VSA-table
    Map<Address, BlockVSA> m_blocks;  // All blocks in this function

    static final String [] x86Regs = {"RAX", "RBX", "RCX", "RDX"};

    public FunctionVSA(Program program, Listing listintDB, FunctionDB func, TaskMonitor monitor) {
        m_program = program;
        m_listDB = listintDB;
        m_function = func;

        InitCPUStatus();
        InitVSATable();
        constructCFG();
    }

    private void InitRegisterStatus() {
        /* Set register values to symbols */
        for (String reg: x86Regs) {
            m_registers[reg] = "V" + reg;
        }
    }

    private void InitVSATable() {
        /* initialize m_VSATable */
        for (String reg: x86Regs) {
            Set vs = new Set();
            vs.add("V" + reg);
            m_VSATble[reg] = vs;
        }

        /* Initialzie vsaTalbe for code blocks */
        AddressSetView addresses = thisFunc.getBody();
        CodeBlockModel blockModel = new BasicBlockModel(m_program);
        CodeBlockIterator codeblkIt = blockModel.getCodeBlocksContaining(addresses, m_monitor);

        while (codeblkIt.hasNext()) {
            CodeBlock codeBlk = codeblkIt.next();
            BlockVSA vsaBlk = new BlockVSA(codeBlock);
            Address addrStart = codeBlk.getMinaddress();
            m_blocks[addrStart] = blk;
        }
    }

    private void constructCFG() {
        for (BlockVSA vsaBlk: m_blocks.values()) {
            CodeBlock codeBlk = vsaBlk.m_block;
            CodeBlock[] nexts;

            CodeBlockReferenceIterator di = codeBlk.getDestinations(monitor);
            while (di.hasNext())  {
                CodeBlockReference ref = di.next();
                CodeBlock blk = ref.getDestinationBlock();
                nexts.add(blk);
            }
            vsaBlk.m_nexts = nexts;
        }
    }

    public boolean doInterpration() {
        CodeBlock firstBlk = getCodeBlockAt(entry, monitor);

        traversBlocks(firstBlk, m_registers);
    }

    boolean traversBlocks(BlockVSA blk, Map<String, String> register_status) {
        Map<String, String> regs;

        regs = blk.doVSA(register_status);
        BlockVSA[] nexts = blk.m_nexts;
        String[] str;

        if (nexts.length >= 1) {
            for (BlockVSA nextBlk: nexts) {
                boolean bLoopBack = (nextBlk.m_blk.getMinaddress() < blk.m_blk.getMinaddress());
                if (bLoopBack && blk.getRunCount() > 10) {
                    continue;   // skip this one
                }
                else {
                    traversBlocks(nextBlk, regs);
                }
            }
        }
        return true;
    }

    boolean mergeVSATables() {
        for (BlockVSA blk: m_blocks) {
            Map<String, Set> table = blk.getVSATable();

            /* merge two tables */
        }
    }

    boolean structAnalysis() {

    }
}


/* just for x86-64 */
class BlockVSA {
    Program m_program;
    Listing m_listDB;
    Map<String, String> m_registers;
    Map<String, Set> m_VSATble;

    public CodeBlock m_block;
    public CodeBlock[] m_nexts;
    private int m_runs;

    final OperandType OPRDTYPE;

    public BlockVSA(Program program, Listing listintDB, CodeBlock blk) {
        m_program = prog;
        m_listDB = listintDB;
        m_block = blk;

        m_VSATble = new Map<String, String>();
        OPRDTYPE = new OperandType();
        m_runs = 0;
    }

    void doVSA(Map<String, String> register_status) {
        m_runs += 1;
        m_registers = register_status;
        Address addrStart = blk.getMinaddress();
        Address addrEnd = blk.getMaxAddress();
        Addresset addrSet = Addresset(addrStart, addrEnd);
        InstructionIterator iiter = listDB.getInstructions(set, true);

        String tmpAddr = null;
        String tmpValue = null;
        Set tmpSet = null;

        while (iiter.hasNext() && !monitor.isCancelled()) {

            InstructionDB inst = (InstructionDB)iiter.next();
            String op = instr.getMnemonicString();

            if(op.equals("push")) {
                String oprd = inst.getDefaultOperandRepresentation(0);
                int oprdty = inst.getOperandType(0);

                /* Get oprand value & upadte VSA-table */
                if (OPRDTYPE.isRegister(oprdty)) { // register
                    tmpValue = regStatus[oprd];
                }
                else if (OPRDTYPE.isScalar(oprdty)){ // Constant value
                    tmpValue = oprd;
                }
                else { // must be address: two memory oprand does't supported by x86 and ARM
                    System.out.println("Wrong operand");
                }

                tmpAddr = regStatus["RSP"];
                tmpSet = vsaTble[tmpAddr];
                if (tmpSet == null) {
                    tmpSet = new Set();
                    vsaTble[tmpAddr] = tmpSet;
                }
                tmpSet.append(tmpValue);

                /* Update VSA-table for RSP */
                tmpValue = regStatus["RSP"];
                tmpValue = symbolSub(tmpValue, 8);
                tmpSet = vsaTble["RSP"];
                assert(tmpSet != null);
                tmpSet.append(tmpValue);

                /* Update RSP register status */
                tmpValue = regStatus["RSP"];
                tmpValue = symbolSub(tmpValue, 8);
                regStatus["RSP"] = tmpValue;
            }

            else if (op.equals("pop")) {
                String oprd = inst.getDefaultOperandRepresentation(0);
                int oprdty = inst.getOperandType(0);

                /* operand must be a reigster. Other type of memory access does't supported by x86 and ARM  */
                assert(OPRDTYPE.isRegister(oprdty));

                /* Get value from stack && update rigister status */
                tmpValue = regStatus["RSP"];
                tmpSet = vsaTble[tmpValue];
                assert(tmpSet != null);
                regStatus[oprd] = tmpValue;

                /* Update RSP register status */
                tmpValue = regStatus["RSP"];
                tmpValue = symbolAdd(tmpValue, 8);
                regStatus["RSP"] = tmpValue;
            }

            else if (op.equals("add")) {
                continue;
            }
            else if (op.equals("sub")) {
                continue;
            }
            else {
                continue;
            }
        }
    }

    /* fix me */
    String symbolAdd(String symbol, long value) {
        return symbol + "+" + String(value);
    }

    /* fix me */
    String symbolSub(String symbol, long value) {
        return symbol + "-" + String(value);
    }

    /* fix me */
    String symbolMul(String symbol, long value) {
        return symbol + "x" + String(value);
    }

    /* fix me */
    String symbolDivd(String symbol, long value) {
        return symbol + "/" + String(value);
    }

    int getRunCount() {
        return m_runs;
    }
}
package symbolicVSA;

import java.util.*;

import symbolicVSA.*;
import symbolicVSA.operand.*;

class UnspportInstruction extends VSAException {
    private Instruction m_inst;

    UnspportInstruction(Instruction instr) {
        m_inst = instr;
    }

    public String toString() {
        String msg = String.format("Unsupported instruction -> %s", m_inst.toString());
        return msg;
    }
}

class InvalidOperand extends VSAException {
    private Instruction m_inst;
    private Object[] m_objs;

    InvalidOperand(Instruction instr, int operand_index) {
        m_inst = instr;
        m_objs = instr.getOpObjects(operand_index);
    }

    InvalidOperand(Object[] objs_of_MemOperand) {
        m_inst = null;
        m_objs = objs_of_MemOperand;
    }

    public String toString() {
        /* print some details */
        String[] msg = new String[m_objs.length + 1];

        for (int i = 0; i < m_objs.length; i++) {
            Object o = m_objs[i];

            if (o instanceof String)
                msg[i] = new String((String) o);
            else if (o instanceof Character)
                msg[i] = new String(Character.toString((Character) o));
            else
                msg[i] = new String(o.getClass().getName());
        }
        if (m_inst == null)
            msg[m_objs.length] = "";
        else
            msg[m_objs.length] = " @ " + m_inst.toString();

        return String.join(";", msg);
    }
}

class Interpreter {
    public boolean doRecording(Instruction inst) {
        System.out.println("91:" + inst.toString());
        return true;
    }
}

public class X86Interpreter extends Interpreter {

    private static X86Processor m_CPU; // x86-64 CPU
    private static OperandType m_OPRDTYPE; // Use for testing opranad types
    private static SymbolicCalculator m_SymCalc; // Used for do symbolic calculation

    private Map<Long, Map<String, Set<String>>> m_SMART; // Memory access recording
    private MachineState m_MachState; // Machine state

    private static X86Interpreter m_singleton = null;

    private X86Interpreter() {
        m_CPU = X86Processor.getProcessor();
        m_SymCalc = SymbolicCalculator.getCalculator();
        m_OPRDTYPE = new OperandType();
    }

    public static X86Interpreter getInterpreter() {
        if (m_singleton == null) {
            m_singleton = new X86Interpreter();
        }
        return m_singleton;
    }

    public X86Processor getCPU() {
        return m_CPU;
    }

    /**
     * Recording memroy accessing into @param table
     * We deal with exceptions including UnsupportedInstruction and InvalidOperand in this boundary
     * @param state
     * @param table
     * @param inst
     * @return
     */
    public boolean doRecording(MachineState state, Map<Long, Map<String, Set<String>>> table, Instruction inst) {
        m_MachState = state;
        m_SMART = table;

        int nOprand = inst.getNumOperands();

        try {
            if (nOprand == 0) {
                _doRecording0(inst);
            } else if (nOprand == 1) {
                _doRecording1(inst);
            } else if (nOprand == 2) {
                _doRecording2(inst);
            } else if (nOprand == 3) {
                _doRecording3(inst);
            } else {
                /* Throw exception */
                throw new UnspportInstruction(inst);
            }
            return true;

        } catch (UnspportInstruction e) {
            String fname = e.getStackTrace()[0].getFileName();
            int line = e.getStackTrace()[0].getLineNumber();

            System.err.println(String.format("%s:%d: %s", fname, line, e.toString()));
            return false;
        }
    }

    public boolean doRecording(MachineState state, SMARTable table, Instruction inst) {
        return doRecording(state, table.m_tbl, inst);
    }

    private void _doRecording0(Instruction inst) {
        // System.out.println("331: " + inst.toString());
        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("nop")) {
            return;
        }

        else if (op.equalsIgnoreCase("hlt")) {
            return;
        }

        else if (op.equalsIgnoreCase("cbw") || op.equalsIgnoreCase("cwde") || op.equalsIgnoreCase("cdqe")) {
            /* CBW/CWDE/CDQE: AX ← sign-extend of AL. */
            return;
        }

        else if (op.equalsIgnoreCase("ret")) {
            _record0ret(inst);
        }

        else if (op.equalsIgnoreCase("leave")) {
            _record0leave(inst);
        }

        else {
            throw new UnspportInstruction(inst);
        }
    }

    private void _record0ret(Instruction inst) {
        String strValue;

        /* Update RSP register status */
        strValue = getRegisterValue("RSP");
        strValue = m_SymCalc.symbolicAdd(strValue, 8);
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strValue);
    }

    private void _record0leave(Instruction inst) {
        /* mov rsp, rbp; pop rbp */
        String strValSP, strValBP;
        String strValue;

        /* mov rsp, rbp */
        strValBP = getRegisterValue("RBP");
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strValBP);

        /* pop rbp */
        strValSP = getRegisterValue("RSP");
        strValue = getMemoryValue(strValSP);
        updateRegisterWriteAccess(inst.getAddress(), "RBP", strValue);

        /* Clean memory status */
        strValSP = getRegisterValue("RSP");
        m_MachState.untouchMemAddr(strValSP);

        /* Update register RSP */
        strValSP = getRegisterValue("RSP");
        strValue = m_SymCalc.symbolicAdd(strValSP, 8);
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strValue);
    }

    private void _doRecording1(Instruction inst) {
        // System.out.println("340: " + inst.toString());
        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("push")) {
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
            _record1call(inst);

        } 
        
        else if (op.charAt(0) == 'j' || op.charAt(0) == 'J') {
            /* jump xxx & jcc xx */
            System.out.println("405: fix-me, jxx");
        } 
        
        else if (op.equalsIgnoreCase("ret")) {
            /* retn 0x8 */
            _record1retn(inst);
        }

        else {
            throw new UnspportInstruction(inst);
        }
    }

    /**
     * PUSH r/m16; PUSH r/m32; PUSH r/m64; PUSH r16; PUSH r32; PUSH r64; PUSH imm8;
     * PUSH imm16; PUSH imm32; PUSH CS; PUSH SS; PUSH DS; PUSH ES; PUSH FS; PUSH GS;
     * 
     * @param inst
     */
    private void _record1push(Instruction inst) {
        int oprdty = inst.getOperandType(0);
        Object[] objs = inst.getOpObjects(0);
        String strAddr, strValue;

        /* Get oprand value & update MAR-table */
        if (m_OPRDTYPE.isRegister(oprdty)) { // register
            Register r = (Register) objs[0];
            strValue = getRegisterValue(r);

        } else if (m_OPRDTYPE.isScalar(oprdty)) { // Constant value
            Scalar s = (Scalar) objs[0];
            strValue = String.valueOf(s.getValue());

        } else {
            /* must be address */
            strAddr = _calcMemAddress(inst.getDefaultOperandRepresentation(0), objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr);

            /* fetch the value from the memory elememt */
            strValue = getMemoryValue(strAddr);
        }

        /* Update MAR-table & register status */
        strAddr = getRegisterValue("RSP");
        strAddr = m_SymCalc.symbolicSub(strAddr, 8);
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strAddr);

        /* Update MAR-table & memory status */
        strAddr = getRegisterValue("RSP");
        updateMemoryWriteAccess(inst.getAddress(), strAddr, strValue);
    }

    private void _record1pop(Instruction inst) {
        /* pop reg */
        int oprdty = inst.getOperandType(0);
        Object[] objs = inst.getOpObjects(0);
        String strValue;

        /*
         * operand must be a reigster. Other type of memory access does't supported by
         * x86 and ARM
         */
        if (!m_OPRDTYPE.isRegister(oprdty)) {
            throw new InvalidOperand(inst, 0);
        }
        Register r = (Register) objs[0];
        // strAddr = getRegisterValue("RSP");
        // updateMemoryReadAccess(inst.getAddress(), strAddr);

        /* Get value from stack && update rigister status */
        strValue = getMemoryValue(getRegisterValue("RSP"));
        updateRegisterWriteAccess(inst.getAddress(), r, strValue);

        /* Clean memory status */
        m_MachState.untouchMemAddr(getRegisterValue("RSP"));

        /* Update RSP register status */
        strValue = m_SymCalc.symbolicAdd(getRegisterValue("RSP"), 8);
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strValue);
    }

    private void _record1div(Instruction inst) {
        /* DIV r/m8 */
        int oprdty = inst.getOperandType(0);
        Object[] objs = inst.getOpObjects(0);

        String strAddr, strValue;
        if (m_OPRDTYPE.isRegister(oprdty)) {
            /* Div reg */
            Register r = (Register) objs[0];
            strValue = getRegisterValue(r);
        } else if (m_OPRDTYPE.isScalar(oprdty)) {
            /* Div 8; */
            Scalar s = (Scalar) objs[0];
            strValue = String.valueOf(s.getValue());
        } else {
            /* others */
            strAddr = _calcMemAddress(inst.getDefaultOperandRepresentation(0), objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr);

            /* fetch the value from the memory elememt */
            strValue = getMemoryValue(strAddr);
        }

        String strDx, strAx, strQue, strRem;
        long iDx, iAx, iQue, iRem;

        strDx = getRegisterValue("RDX");
        strAx = getRegisterValue("RAX");

        if (m_SymCalc.isPureSymbolic(strDx) || m_SymCalc.isPureSymbolic(strAx)) {
            strDx = strDx.replaceAll("\\s+", "");
            strAx = strAx.replaceAll("\\s+", "");

            strQue = String.format("D(%s:%s/%s)", strDx, strAx, strValue);
            strRem = String.format("D(%s:%s%%%s)", strDx, strAx, strValue);
        } else {
            iDx = Long.decode(strDx);
            iAx = Long.decode(strAx);
            if (m_SymCalc.isPureSymbolic(strValue)) {
                strDx = strDx.replaceAll("\\s+", "");
                strAx = strAx.replaceAll("\\s+", "");

                strQue = String.format("D(%s:%s/%s)", strDx, strAx, strValue);
                strRem = String.format("D(%s:%s%%%s)", strDx, strAx, strValue);
            } else {
                iQue = (iDx * iAx) / Long.decode(strValue);
                iRem = (iDx * iAx) % Long.decode(strValue);
                strQue = String.valueOf(iQue);
                strRem = String.valueOf(iRem);
            }
        }

        /* upate register status */
        updateRegisterWriteAccess(inst.getAddress(), "RAX", strQue);
        updateRegisterWriteAccess(inst.getAddress(), "RDX", strRem);
    }

    private void _record1call(Instruction inst) {
        Object[] objs = inst.getOpObjects(0);
        String strValue, strValSP;

        // Scalar s = (Scalar) objs[0];

        // /* Update RSP register status */
        // strValSP = getRegisterValue("RSP");
        // strValue = m_SymCalc.symbolicAdd(strValSP, s.getValue() + 8);
        // updateRegisterWriteAccess(inst.getAddress(), "RSP", strValue);

        System.out.println("400: fix-me, call xxx" + "");
    }

    private void _record1retn(Instruction inst) {
        Object[] objs = inst.getOpObjects(0);
        String strValue, strValSP;

        Scalar s = (Scalar) objs[0];

        /* Update RSP register status */
        strValSP = getRegisterValue("RSP");
        strValue = m_SymCalc.symbolicAdd(strValSP, s.getValue() + 8);
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strValue);
    }

    private void _doRecording2(Instruction inst) {
        // System.out.println("414: " + inst.toString());
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

        else if (op.equalsIgnoreCase("movzx")) {
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

        else if (op.equalsIgnoreCase("and")) {
            return;
        }

        else if (op.equalsIgnoreCase("or")) {
            return;
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

        else if (op.equalsIgnoreCase("sal")) {
            _record2sal(inst);
        }

        else if (op.equalsIgnoreCase("sar")) {
            _record2sar(inst);
        }

        else if (op.equalsIgnoreCase("and")) {
            _record2sar(inst);
        }

        else if (op.equalsIgnoreCase("imul")) {
            _record2imul(inst);
        }

        else {
            throw new UnspportInstruction(inst);
        }
    }

    private void _record2addsub(Instruction inst, char op) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);
        String strVal0, strVal1, strRes;

        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            Register rOprd0 = (Register) objs0[0];
            strVal0 = getRegisterValue(rOprd0);

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                /* sub reg, reg */
                Register rOprd1 = (Register) objs1[0];
                strVal1 = getRegisterValue(rOprd1);

                if (op == '+')
                    strRes = m_SymCalc.symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strRes = m_SymCalc.symbolicSub(strVal0, strVal1);
                else
                    strRes = strVal0; // fix-me

                updateRegisterWriteAccess(inst.getAddress(), rOprd0, strRes);

            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                /* sub rsp, 8; */
                Scalar sOprd1 = (Scalar) objs1[0];

                if (op == '+')
                    strRes = m_SymCalc.symbolicAdd(strVal0, sOprd1.getValue());
                else if (op == '-')
                    strRes = m_SymCalc.symbolicSub(strVal0, sOprd1.getValue());
                else
                    strRes = strVal0;

                /* upate register status */
                updateRegisterWriteAccess(inst.getAddress(), rOprd0, strRes);

            } else {
                /* others */
                String strAddr1 = _calcMemAddress(inst.getDefaultOperandRepresentation(1), objs1);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemoryValue(strAddr1);

                if (op == '+')
                    strRes = m_SymCalc.symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strRes = m_SymCalc.symbolicSub(strVal0, strVal1);
                else
                    strRes = strVal0;

                /* upate register status */
                updateRegisterWriteAccess(inst.getAddress(), rOprd0, strRes);
            }
        } else {
            /* The first operand is in memory */
            /* Ghidra bug: sub [RAX],RDX -> _, ADDR|REG */
            String strAddr0 = _calcMemAddress(inst.getDefaultOperandRepresentation(0), objs0);
            /* fetch the value from the memory elememt */
            strVal0 = getMemoryValue(strAddr0);

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                Register rOprd1 = (Register) objs1[0];
                strVal1 = getRegisterValue(rOprd1);

            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                Scalar sOprd1 = (Scalar) objs1[0];
                strVal1 = String.valueOf(sOprd1.getValue());
            } else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand(inst, 1);
            }

            if (op == '+')
                strRes = m_SymCalc.symbolicAdd(strVal0, strVal1);
            else if (op == '-')
                strRes = m_SymCalc.symbolicSub(strVal0, strVal1);
            else
                strRes = strVal0;

            /* update memory write access */
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
        }
    }

    private void _record2mov(Instruction inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);

        /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            Register rOprd0 = (Register) objs0[0];
            String strAddr1, strVal1;

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                /* mov reg, reg */
                Register rOprd1 = (Register) objs1[0];

                strVal1 = getRegisterValue(rOprd1);
                updateRegisterWriteAccess(inst.getAddress(), rOprd0, strVal1);

            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                /* mov rax, 8; */
                Scalar sOprd1 = (Scalar) objs1[0];

                strVal1 = String.valueOf(sOprd1.getValue());
                updateRegisterWriteAccess(inst.getAddress(), rOprd0, strVal1);

            } else { /* memory oprand */
                strAddr1 = _calcMemAddress(inst.getDefaultOperandRepresentation(1), objs1);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemoryValue(strAddr1);

                /* upate register status */
                updateRegisterWriteAccess(inst.getAddress(), rOprd0, strVal1);
            }
        } else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            String strAddr0, strVal1;

            strAddr0 = _calcMemAddress(inst.getDefaultOperandRepresentation(0), objs0);

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                Register rOprd1 = (Register) objs1[0];
                strVal1 = getRegisterValue(rOprd1);

            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                Scalar sOprd1 = (Scalar) objs1[0];
                strVal1 = m_SymCalc.symbolicAdd("0", sOprd1.getValue());

            } else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand(inst, 1);
            }

            /* update memory write access */
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strVal1);
        }
    }

    private void _record2lea(Instruction inst) {
        int oprd0ty = inst.getOperandType(0);
        // int oprd1ty = inst.getOperandType(1);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);

        /* get the name of register */
        if (!m_OPRDTYPE.isRegister(oprd0ty)) {
            throw new InvalidOperand(inst, 0);
        }
        Register rOprd0 = (Register) objs0[0];

        /* get the value of second operand */
        String strAddr1 = _calcMemAddress(inst.getDefaultOperandRepresentation(1), objs1);

        /* upate register status */
        updateRegisterWriteAccess(inst.getAddress(), rOprd0, strAddr1);
    }

    private void _record2xor(Instruction inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);
        String strVal0, strVal1, strRes;

        /* xor reg, reg; xor reg, mem; xor reg, 0x1234; xor mem, reg; xor mem, 0x1234 */
        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            Register rOprd0 = (Register) objs0[0];
            strVal0 = getRegisterValue(rOprd0);

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                /* xor reg, reg */
                Register rOprd1 = (Register) objs1[0];
                strVal1 = getRegisterValue(rOprd1);

            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                /* xor rax, 8; */
                Scalar sOprd1 = (Scalar) objs1[0];
                strVal1 = String.valueOf(sOprd1.getValue());

            } else { /* memory oprand */
                String strAddr1 = _calcMemAddress(inst.getDefaultOperandRepresentation(1), objs1);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemoryValue(strAddr1);
            }
            /* upate register status */
            strRes = m_SymCalc.symbolicXor(strVal0, strVal1);
            updateRegisterWriteAccess(inst.getAddress(), rOprd0, strRes);

        } else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            String strAddr0 = _calcMemAddress(inst.getDefaultOperandRepresentation(0), objs0);
            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr0);
            /* fetch the value from the memory elememt */
            strVal0 = getMemoryValue(strAddr0);

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                Register rOprd1 = (Register) objs1[0];
                strVal1 = getRegisterValue(rOprd1);

            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                Scalar sOprd1 = (Scalar) objs1[0];
                strVal1 = String.valueOf(sOprd1.getValue());

            } else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand(inst, 1);
            }

            /* update memory write access */
            strRes = m_SymCalc.symbolicXor(strVal0, strVal1);

            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
        }
    }

    private void _record2test(Instruction inst) {
        /*
         * test reg, reg; test reg, mem; test reg, 0x1234; test mem, reg; test mem,
         * 0x1234
         */
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);

        /* test oprand 0 */
        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            /* do nothing */
        } else if (m_OPRDTYPE.isScalar(oprd0ty)) {
            throw new InvalidOperand(inst, 0);

        } else {
            /* memory oprand */
            String strAddr0 = _calcMemAddress(inst.getDefaultOperandRepresentation(0), objs0);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr0);
        }

        /* test oprand 1 */
        if (m_OPRDTYPE.isRegister(oprd1ty)) {
            /* do nothing */
        } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
            /* do nothing */
        } else {
            /* memory oprand */
            String strAddr1 = _calcMemAddress(inst.getDefaultOperandRepresentation(1), objs1);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr1);
        }
    }

    /**
     * SHL r/m8, 1 SHL r/m8**, 1 SHL r/m8, CL SHL r/m8**, CL SHL r/m8, imm8
     * 
     * @param inst
     */
    private void _record2shl(Instruction inst) {
        __record2shift(inst, '*');
    }

    /**
     * SHR r/m8,1 SHR r/m8**, 1 SHR r/m8, CL SHR r/m8**, CL SHR r/m8, imm8
     * SHR r/m8**, imm8
     * 
     * @param inst
     */
    private void _record2shr(Instruction inst) {
        __record2shift(inst, '/');
    }

    /**
     * SAL r/m8, 1 SAL r/m8**, 1 SAL r/m8, CL SAL r/m8**, CL SAL r/m8, imm8
     * SAL r/m8**, imm8
     * 
     * @param inst
     */
    private void _record2sal(Instruction inst) {
        __record2shift(inst, '*');
    }

    /**
     * SAR r/m8, 1 SAR r/m8**, 1 SAR r/m8, CL SAR r/m8**, CL SAR r/m8, imm8
     * SAR r/m8**, imm8
     * 
     * @param inst
     */
    private void _record2sar(Instruction inst) {
        __record2shift(inst, '/');
    }

    private void __record2shift(Instruction inst, char op) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);
        String strVal0, strVal1, strRes;

        /* check oprand 1 */
        if (m_OPRDTYPE.isScalar(oprd1ty)) {
            Scalar s = (Scalar) objs1[0];
            strVal1 = String.valueOf(s.getValue());
        } else if (m_OPRDTYPE.isRegister(oprd1ty)) {
            Register r = (Register) objs1[0];
            strVal1 = getRegisterValue(r);
        } else {
            throw new InvalidOperand(inst, 1);
        }

        /* check oprand 0 */
        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            Register r = (Register) objs0[0];
            strVal0 = getRegisterValue(r);

            if (op == '*') {
                if (m_SymCalc.isPureDigital(strVal1)) {
                    strRes = m_SymCalc.symbolicMul(strVal0, (long) Math.pow(2, Long.decode(strVal1)));
                } else {
                    strRes = m_SymCalc.symbolicMul(strVal0, strVal1 + "2P");
                }
            } else if (op == '/') {
                if (m_SymCalc.isPureDigital(strVal1)) {
                    strRes = m_SymCalc.symbolicDiv(strVal0, (long) Math.pow(2, Long.decode(strVal1)));
                } else {
                    strRes = m_SymCalc.symbolicDiv(strVal0, strVal1 + "2P");
                }
            } else {
                throw new InvalidOperand(inst, 1);
            }

            /* upate register status */
            updateRegisterWriteAccess(inst.getAddress(), r, strRes);

        } else {
            String strAddr0 = _calcMemAddress(inst.getDefaultOperandRepresentation(0), objs0);

            strVal0 = getMemoryValue(strAddr0);

            if (op == '*') {
                if (m_SymCalc.isPureDigital(strVal1)) {
                    strRes = m_SymCalc.symbolicMul(strVal0, (long) Math.pow(2, Long.decode(strVal1)));
                } else {
                    strRes = m_SymCalc.symbolicMul(strVal0, strVal1 + "2P");
                }
            } else if (op == '/') {
                if (m_SymCalc.isPureDigital(strVal1)) {
                    strRes = m_SymCalc.symbolicDiv(strVal0, (long) Math.pow(2, Long.decode(strVal1)));
                } else {
                    strRes = m_SymCalc.symbolicDiv(strVal0, strVal1 + "2P");
                }
            } else {
                throw new InvalidOperand(inst, 1);
            }
            /* Update memory write access */
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
        }
    }

    /*
     * IMUL r16,r/m16; IMUL r32,r/m32; IMUL r16,imm8; IMUL r32,imm8; IMUL r16,imm16
     * IMUL r32,imm32;
     */
    private void _record2imul(Instruction inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);
        String strVal0, strVal1, strRes;

        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            Register rOprd0 = (Register) objs0[0];
            strVal0 = getRegisterValue(rOprd0);

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                /* imul reg, reg */
                Register rOprd1 = (Register) objs1[0];
                strVal1 = getRegisterValue(rOprd1);

            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                /* xor rax, 8; */
                Scalar sOprd1 = (Scalar) objs1[0];
                strVal1 = String.valueOf(sOprd1.getValue());

            } else { /* memory oprand */
                String strAddr1 = _calcMemAddress(inst.getDefaultOperandRepresentation(1), objs1);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemoryValue(strAddr1);
            }
            /* upate register status */
            strRes = m_SymCalc.symbolicMul(strVal0, strVal1);
            updateRegisterWriteAccess(inst.getAddress(), rOprd0, strRes);

        } else {
            /* Operand 1 is invalid, throw exeception */
            throw new InvalidOperand(inst, 2);
        }
    }

    private void _doRecording3(Instruction inst) {
        // System.out.println("1035: " + inst.toString());

        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("imul")) {
            /* sub reg, reg; sub reg, 0x1234; sub reg, mem; sub mem, reg; sub mem, 0x1234 */
            _record3imul(inst);
        } else {
            throw new UnspportInstruction(inst);
        }
    }

    private void _record3imul(Instruction inst) {
        /* IMUL r16,r/m16,imm16 */
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        int oprd2ty = inst.getOperandType(2);
        Object[] objs0 = inst.getOpObjects(0);
        Object[] objs1 = inst.getOpObjects(1);
        Object[] objs2 = inst.getOpObjects(2);
        String strVal1, strRes;

        /* test oprand 0 */
        if (!(m_OPRDTYPE.isRegister(oprd0ty) && m_OPRDTYPE.isScalar(oprd2ty))) {
            throw new InvalidOperand(inst, 0);
        }

        Register rOprd0 = (Register) objs0[0];

        if (m_OPRDTYPE.isRegister(oprd1ty)) {
            Register r = (Register) objs1[0];
            strVal1 = getRegisterValue(r);

        } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
            throw new InvalidOperand(inst, 1);

        } else {
            /* memory oprand */
            String strAddr1 = _calcMemAddress(inst.getDefaultOperandRepresentation(1), objs1);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr1);

            /* fetch the value from the memory elememt */
            strVal1 = getMemoryValue(strAddr1);
        }

        Scalar sOprd2 = (Scalar) objs2[0];
        strRes = m_SymCalc.symbolicMul(strVal1, sOprd2.getValue());

        /* upate register status */
        updateRegisterWriteAccess(inst.getAddress(), rOprd0, strRes);
    }

    /**
     * We need oprd_exp to parse the operations among objects
     * 
     * @param oprd_exp
     * @param objs_of_MemOperand
     * @return
     */
    private String _calcMemAddress(String oprd_exp, Object[] objs_of_MemOperand) {
        /* A memory oprand from Ghidra, consits with an array of objects */
        Object[] objs = objs_of_MemOperand;
        String strValue, strAddress;

        if (objs.length == 1) {
            /* mov reg, [reg]; mov reg, [0x48000] */
            if (objs[0] instanceof Register) {
                Register r = (Register) objs[0];

                /* get regiser value */
                strValue = getRegisterValue(r.getName());
                return strValue;
            } else if (objs[0] instanceof Scalar) {
                Scalar s = (Scalar) objs[0];

                /* get memory address */
                strAddress = String.valueOf(s.getValue());
                return strAddress;

            } else if (objs[0] instanceof GenericAddress) {
                GenericAddress a = (GenericAddress) objs[0];

                strAddress = String.valueOf(a.getOffset());
                return strAddress;

            } else {
                /* This operand is invalid, throw exeception */
                throw new InvalidOperand(objs_of_MemOperand);
            }
        } else if (objs.length == 2) {
            /*
             * Registet + Scaler: i.e [RBP + -0x28] Registet + Scaler: [-0xf8 + RBP], LEA
             * RDX,[RAX*0x4]
             */
            String[] parts = oprd_exp.split("\\s", 0);
            Register r;
            Scalar s;

            if (parts.length == 1) {
                r = (Register) objs[0];
                s = (Scalar) objs[1];

                strValue = getRegisterValue(r.getName());
                strAddress = m_SymCalc.symbolicMul(strValue, s.getValue());
            } else {
                if ((objs[0] instanceof Register) && (objs[1] instanceof Scalar)) {
                    r = (Register) objs[0];
                    s = (Scalar) objs[1];
                } else if ((objs[0] instanceof Scalar) && (objs[1] instanceof Register)) {
                    r = (Register) objs[1];
                    s = (Scalar) objs[0];
                } else {
                    throw new InvalidOperand(objs_of_MemOperand);
                }
                strValue = getRegisterValue(r.getName());
                strAddress = m_SymCalc.symbolicAdd(strValue, s.getValue());
            }
            return strAddress;

        } else if (objs.length == 3) {
            /* Registet + Register * Scaler: [RDX + RAX*0x1] */
            if ((objs[0] instanceof Register) && (objs[1] instanceof Register) && (objs[2] instanceof Scalar)) {
                Register rb, ri;
                Scalar s;
                String vb, vi;

                rb = (Register) objs[0];
                ri = (Register) objs[1];
                s = (Scalar) objs[2];

                vb = getRegisterValue(rb.getName());
                vi = getRegisterValue(ri.getName());

                strValue = m_SymCalc.symbolicMul(vi, s.getValue());
                strAddress = m_SymCalc.symbolicAdd(vb, strValue);

                return strAddress;
            } else {
                throw new InvalidOperand(objs_of_MemOperand);
            }
        } else if (objs.length == 4) {
            /* [RBP + RAX*0x4 + -0x60] */
            /* MOV [-0x1a0 + RBP + RAX*0x4],EDX */
            Register rb, ri;
            Scalar sc, so;
            String vb, vi;

            if ((objs[0] instanceof Register) && (objs[1] instanceof Register) && (objs[2] instanceof Scalar)
                    && (objs[3] instanceof Scalar)) {

                rb = (Register) objs[0];
                ri = (Register) objs[1];
                sc = (Scalar) objs[2];
                so = (Scalar) objs[3];
            } else if ((objs[0] instanceof Scalar) && (objs[1] instanceof Register) && (objs[2] instanceof Register)
                    && (objs[3] instanceof Scalar)) {

                rb = (Register) objs[1];
                ri = (Register) objs[2];
                sc = (Scalar) objs[3];
                so = (Scalar) objs[0];

            } else {
                throw new InvalidOperand(objs_of_MemOperand);
            }

            vb = getRegisterValue(rb.getName());
            vi = getRegisterValue(ri.getName());

            strValue = m_SymCalc.symbolicMul(vi, sc.getValue());
            strAddress = m_SymCalc.symbolicAdd(vb, strValue);
            strAddress = m_SymCalc.symbolicAdd(strAddress, so.getValue());

            return strAddress;

        } else {
            /* This operand is invalid, throw exeception */
            throw new InvalidOperand(objs_of_MemOperand);
        }
    }

    private String getRegisterValue(String register) {
        String Reg = m_CPU.getRegisterFullName(register);
        return m_MachState.getRegValue(Reg);
    }

    private String getRegisterValue(Register register) {
        String Reg = m_CPU.getRegisterFullName(register.getName());
        return m_MachState.getRegValue(Reg);
    }

    /* override me if needs */
    private String getMemoryValue(String address) {
        return m_MachState.getMemValue(address);
    }

    private boolean updateRegisterWriteAccess(long inst_address, String reg, String value) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;

        /* Update SMAR-table for Register reg */
        tmpMap = m_SMART.get(inst_address);
        if (tmpMap == null) {
            tmpMap = new HashMap<>();
            m_SMART.put(inst_address, tmpMap);
        }

        reg = m_CPU.getRegisterFullName(reg);
        tmpSet = tmpMap.get(reg);
        if (tmpSet == null) {
            tmpSet = new HashSet<>();
            tmpMap.put(reg, tmpSet);
        }

        // assert (tmpSet != null);
        tmpSet.add(value);

        /* for debugging */
        // System.out.println(String.format("674: @0x%x: %s = %s", inst_address, reg, value));

        /* Update register state */
        m_MachState.setRegValue(reg, value);

        return true;
    }

    private boolean updateRegisterWriteAccess(Address instruction_address, Register reg, String value) {
        return updateRegisterWriteAccess(instruction_address.getOffset(), reg.getName(), value);
    }

    private boolean updateRegisterWriteAccess(Address instruction_address, String reg, String value) {
        return updateRegisterWriteAccess(instruction_address.getOffset(), reg, value);
    }

    private boolean updateMemoryWriteAccess(long inst_address, String address, String value) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;

        /* Update MAR-table for address */
        tmpMap = m_SMART.get(inst_address);
        if (tmpMap == null) {
            tmpMap = new HashMap<>();
            m_SMART.put(inst_address, tmpMap);
        }

        tmpSet = tmpMap.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<>();
            tmpMap.put(address, tmpSet);
        }

        // assert (tmpSet != null);
        tmpSet.add(value);

        /* for debuging */
        // System.out.println(String.format("686: @0x%x: [%s] = %s", inst_address, address, value));

        /* Update memory status */
        m_MachState.setMemValue(address, value);

        return true;
    }

    private boolean updateMemoryWriteAccess(Address inst_address, String memory_address, String value) {
        return updateMemoryWriteAccess(inst_address.getOffset(), memory_address, value);
    }

    private boolean updateMemoryReadAccess(long inst_address, String address) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;
        String value;

        value = m_MachState.getMemValue(address);

        /* Update MAR-table for memory read */
        tmpMap = m_SMART.get(inst_address);
        if (tmpMap == null) {
            tmpMap = new HashMap<>();
            m_SMART.put(inst_address, tmpMap);
        }

        tmpSet = tmpMap.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<>();
            tmpMap.put(address, tmpSet);

            tmpSet.add(value); // Set a symbolic value
        }

        return true;
    }

    private boolean updateMemoryReadAccess(Address inst_address, String memory_address) {
        return updateMemoryReadAccess(inst_address.getOffset(), memory_address);
    }
}

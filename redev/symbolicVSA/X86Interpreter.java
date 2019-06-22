package symbolicVSA;

import java.util.*;

import symbolicVSA.*;
import symbolicVSA.operand.*;

class UnspportInstruction extends VSAException {
    private String m_lineno;
    private Instruction m_inst;

    UnspportInstruction(String lineno, Instruction instr) {
        m_lineno = lineno;
        m_inst = instr;
    }

    public String toString() {
        String msg = String.format("%s: unsupported instruction -> %s", m_lineno, m_inst.toString());
        return msg;
    }
}

class InvalidOperand extends VSAException {
    private String m_lineno;
    private Instruction m_inst;
    private Object[] m_objs;

    InvalidOperand(String lineno, Instruction instr, int operand_index) {
        m_lineno = lineno;
        m_inst = instr;
        m_objs = instr.getOpObjects(operand_index);
    }

    InvalidOperand(String lineno, Object[] objs_of_MemOperand) {
        m_lineno = lineno;
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
            } else if (nOprand == 4) {
                throw new UnspportInstruction("171", inst);
            } else {
                /* Throw exception */
                throw new UnspportInstruction("177", inst);
            }
            return true;

        } catch (Exception e) {
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
        System.out.println("331: " + inst.toString());
        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("nop")) {
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
            throw new UnspportInstruction("333: 0 oprands", inst);
        }
    }

    private void _record0ret(Instruction inst) {
        /* pop rip */
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
        System.out.println("340: " + inst.toString());

        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

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
            System.out.println("400: fix-me, call xxx");
        } else if (op.charAt(0) == 'j' || op.charAt(0) == 'J') {
            /* jump xxx & jcc xx */
            System.out.println("405: fix-me, jxx");
        } else if (op.equalsIgnoreCase("ret")) {
            /* retn 0x8 */
            _record1retn(inst);
        }

        else {
            throw new UnspportInstruction("582: 1 oprands", inst);
        }
    }

    private void _record1push(Instruction inst) {
        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        /* push reg; push 0x1234; */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        /* Get oprand value & upadte MAR-table */
        if (m_OPRDTYPE.isRegister(oprdty)) { // register
            strValue = getRegisterValue(oprd);
        } else if (m_OPRDTYPE.isScalar(oprdty)) { // Constant value
            strValue = oprd;
        } else { // must be address: two memory oprand does't supported by x86 and ARM
            System.out.println("326: throw exception, Wrong operand");
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
        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        /* pop reg */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        /*
         * operand must be a reigster. Other type of memory access does't supported by
         * x86 and ARM
         */
        assert (m_OPRDTYPE.isRegister(oprdty));

        // strAddr = getRegisterValue("RSP");
        // updateMemoryReadAccess(inst.getAddress(), strAddr);

        /* Get value from stack && update rigister status */
        strValue = getRegisterValue("RSP");
        strValue = getMemoryValue(strValue);
        updateRegisterWriteAccess(inst.getAddress(), oprd, strValue);

        /* Clean memory status */
        strValue = getRegisterValue("RSP");
        m_MachState.untouchMemAddr(strValue);

        /* Update RSP register status */
        strValue = getRegisterValue("RSP");
        strValue = m_SymCalc.symbolicAdd(strValue, 8);
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strValue);
    }

    private void _record1div(Instruction inst) {
        /* DIV r/m8 */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        String strAddr, strValue;
        long iVal;

        Object[] objs;

        if (m_OPRDTYPE.isRegister(oprdty)) {
            /* sub reg, reg */
            oprd = inst.getDefaultOperandRepresentation(0);
            strValue = getRegisterValue(oprd);
        } else if (m_OPRDTYPE.isScalar(oprdty)) {
            /* sub rsp, 8; */
            oprd = inst.getDefaultOperandRepresentation(0);
            strValue = oprd;
        } else {
            /* others */
            objs = inst.getOpObjects(0);

            strAddr = _calcMemAddress(objs);

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

    private void _record1retn(Instruction inst) {
        String strValue, strValSP, oprd;

        oprd = inst.getDefaultOperandRepresentation(0);

        /* Update RSP register status */
        strValSP = getRegisterValue("RSP");
        strValue = m_SymCalc.symbolicAdd(strValSP, Integer.decode(oprd) + 8);
        updateRegisterWriteAccess(inst.getAddress(), "RSP", strValue);
    }

    private void _doRecording2(Instruction inst) {
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

    private void _record2addsub(Instruction inst, char op) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            strVal0 = getRegisterValue(oprd0);

            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                /* sub reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegisterValue(oprd1);

                if (op == '+')
                    strValue = m_SymCalc.symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strValue = m_SymCalc.symbolicSub(strVal0, strVal1);
                else
                    strValue = strVal0; // fix-me

                updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                /* sub rsp, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                if (op == '+')
                    strValue = m_SymCalc.symbolicAdd(strVal0, Long.decode(oprd1));
                else if (op == '-')
                    strValue = m_SymCalc.symbolicSub(strVal0, Long.decode(oprd1));
                else
                    strValue = strVal0;

                /* upate register status */
                updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
            } else {
                /* others */
                objs = inst.getOpObjects(1);

                strAddr1 = _calcMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemoryValue(strAddr1);

                if (op == '+')
                    strValue = m_SymCalc.symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strValue = m_SymCalc.symbolicSub(strVal0, strVal1);
                else
                    strValue = strVal0;

                /* upate register status */
                updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
            }
        } else {
            /* The first operand is in memory */
            /* Ghidra bug: sub [RAX],RDX -> _, ADDR|REG */
            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegisterValue(oprd1);
            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            } else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand("773", inst, 1);
            }

            objs = inst.getOpObjects(0);
            strAddr0 = _calcMemAddress(objs);

            /* fetch the value from the memory elememt */
            strVal0 = getMemoryValue(strAddr0);

            if (op == '+')
                strValue = m_SymCalc.symbolicAdd(strVal0, strVal1);
            else if (op == '-')
                strValue = m_SymCalc.symbolicSub(strVal0, strVal1);
            else
                strValue = strVal0;

            /* update memory write access */
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strValue);
        }
    }

    private void _record2mov(Instruction inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                /* mov reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                strVal1 = getRegisterValue(oprd1);
                updateRegisterWriteAccess(inst.getAddress(), oprd0, strVal1);
            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                /* mov rax, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;

                /* upate register status */
                updateRegisterWriteAccess(inst.getAddress(), oprd0, strVal1);
            } else { /* memory oprand */
                objs = inst.getOpObjects(1);
                strAddr1 = _calcMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemoryValue(strAddr1);

                /* upate register status */
                updateRegisterWriteAccess(inst.getAddress(), oprd0, strVal1);
            }
        } else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegisterValue(oprd1);
            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = m_SymCalc.symbolicAdd("0", oprd1);
            } else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand("858", inst, 1);
            }

            objs = inst.getOpObjects(0);

            strAddr0 = _calcMemAddress(objs);

            /* update memory write access */
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strVal1);
        }
    }

    private void _record2lea(Instruction inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* get the name of register */
        assert (m_OPRDTYPE.isRegister(oprd0ty));
        oprd0 = inst.getDefaultOperandRepresentation(0);

        /* get the value of second operand */
        objs = inst.getOpObjects(1);
        strAddr1 = _calcMemAddress(objs);
        strValue = strAddr1;

        /* upate register status */
        updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
    }

    private void _record2xor(Instruction inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            strVal0 = getRegisterValue(oprd0);
            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                /* xor reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                strVal1 = getRegisterValue(oprd1);
            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                /* mov rax, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            } else { /* memory oprand */
                objs = inst.getOpObjects(1);
                strAddr1 = _calcMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(inst.getAddress(), strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemoryValue(strAddr1);
            }

            /* upate register status */
            strValue = m_SymCalc.symbolicXor(strVal0, strVal1);
            updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
        } else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            if (m_OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegisterValue(oprd1);
            } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            } else {
                /* Operand 1 is invalid, throw exeception */
                throw new InvalidOperand("949", inst, 1);
            }

            objs = inst.getOpObjects(0);

            strAddr0 = _calcMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr0);

            /* fetch the value from the memory elememt */
            strVal0 = getMemoryValue(strAddr0);
            /* update memory write access */
            strValue = m_SymCalc.symbolicXor(strVal0, strVal1);

            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strValue);
        }
    }

    private void _record2test(Instruction inst) {
        /*
         * test reg, reg; test reg, mem; test reg, 0x1234; test mem, reg; test mem,
         * 0x1234
         */
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* test oprand 0 */
        if (m_OPRDTYPE.isRegister(oprd0ty)) {
            /* do nothing */
        } else if (m_OPRDTYPE.isScalar(oprd0ty)) {
            throw new InvalidOperand("987", inst, 0);
        } else {
            /* memory oprand */
            objs = inst.getOpObjects(0);
            strAddr0 = _calcMemAddress(objs);

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
            objs = inst.getOpObjects(1);
            strAddr1 = _calcMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr1);
        }
    }

    private void _record2shl(Instruction inst) {
        /* shl rax, 0x4 */

        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* test oprand 0 */
        if (m_OPRDTYPE.isRegister(oprd0ty) && m_OPRDTYPE.isScalar(oprd1ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            oprd1 = inst.getDefaultOperandRepresentation(1);

            strVal0 = getRegisterValue(oprd0);
            iVal1 = Long.decode(oprd1);
            iVal1 = (long) Math.pow(2, iVal1);

            strValue = m_SymCalc.symbolicMul(strVal0, iVal1);

            /* upate register status */
            updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
        } else {
            throw new InvalidOperand("1061", inst, 0);
        }
    }

    private void _record2shr(Instruction inst) {
        /* shr rax, 0x4 */
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* test oprand 0 */
        if (m_OPRDTYPE.isRegister(oprd0ty) && m_OPRDTYPE.isScalar(oprd1ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            oprd1 = inst.getDefaultOperandRepresentation(1);

            strVal0 = getRegisterValue(oprd0);
            iVal1 = Long.decode(oprd1);
            iVal1 = (long) Math.pow(2, iVal1);

            strValue = m_SymCalc.symbolicDiv(strVal0, iVal1);

            /* upate register status */
            updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
        } else {
            throw new InvalidOperand("1092", inst, 0);
        }
    }

    private void _doRecording3(Instruction inst) {
        System.out.println("1035: " + inst.toString());

        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("imul")) {
            /* sub reg, reg; sub reg, 0x1234; sub reg, mem; sub mem, reg; sub mem, 0x1234 */
            _record3imul(inst);
        } else {
            throw new UnspportInstruction("1044: 3 oprands", inst);
        }
    }

    private void _record3imul(Instruction inst) {
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
        assert (m_OPRDTYPE.isRegister(oprd0ty) && m_OPRDTYPE.isScalar(oprd2ty));

        if (m_OPRDTYPE.isRegister(oprd1ty)) {
            oprd1 = inst.getDefaultOperandRepresentation(1);

            strVal1 = getRegisterValue(oprd1);
        } else if (m_OPRDTYPE.isScalar(oprd1ty)) {
            throw new InvalidOperand("1069", inst, 1);
        } else {
            /* memory oprand */
            objs = inst.getOpObjects(1);
            strAddr1 = _calcMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(inst.getAddress(), strAddr1);

            /* fetch the value from the memory elememt */
            strVal1 = getMemoryValue(strAddr1);
        }

        oprd2 = inst.getDefaultOperandRepresentation(2);
        iVal2 = Long.decode(oprd2);
        strValue = m_SymCalc.symbolicMul(strVal1, iVal2);

        /* upate register status */
        oprd0 = inst.getDefaultOperandRepresentation(0);
        updateRegisterWriteAccess(inst.getAddress(), oprd0, strValue);
    }

    private String _calcMemAddress(Object[] objs_of_MemOperand) {
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
            }

            else {
                /* This operand is invalid, throw exeception */
                throw new InvalidOperand("992", objs_of_MemOperand);
            }
        } else if (objs.length == 2) {
            /*
             * Registet + Scaler: i.e [RBP + -0x28] Registet + Scaler: [-0xf8 + RBP]
             */
            Register r;
            Scalar s;

            if ((objs[0] instanceof Register) && (objs[1] instanceof Scalar)) {
                r = (Register) objs[0];
                s = (Scalar) objs[1];
            } else if ((objs[0] instanceof Scalar) && (objs[1] instanceof Register)) {
                r = (Register) objs[1];
                s = (Scalar) objs[0];
            } else {
                throw new InvalidOperand("1019", objs_of_MemOperand);
            }

            strValue = getRegisterValue(r.getName());
            strAddress = m_SymCalc.symbolicAdd(strValue, s.getValue());

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

                System.out.println(String.format("%s + %s*%d?", rb.getName(), ri.getName(), s.getValue()));
                vb = getRegisterValue(rb.getName());
                vi = getRegisterValue(ri.getName());

                strValue = m_SymCalc.symbolicMul(vi, s.getValue());
                strAddress = m_SymCalc.symbolicAdd(vb, strValue);

                return strAddress;
            } else {
                throw new InvalidOperand("1319", objs_of_MemOperand);
            }
        } else if (objs.length == 4) {
            /* [RBP + RAX*0x4 + -0x60] */
            if ((objs[0] instanceof Register) && (objs[1] instanceof Register) && (objs[2] instanceof Scalar)
                    && (objs[3] instanceof Scalar)) {
                Register rb, ri;
                Scalar sc, so;
                String vb, vi;

                rb = (Register) objs[0];
                ri = (Register) objs[1];
                sc = (Scalar) objs[2];
                so = (Scalar) objs[3];

                System.out.println(String.format("%s + %s*0x%x + 0x%x?", rb.getName(), ri.getName(), sc.getValue(),
                        so.getValue()));
                vb = getRegisterValue(rb.getName());
                vi = getRegisterValue(ri.getName());

                strValue = m_SymCalc.symbolicMul(vi, sc.getValue());
                strAddress = m_SymCalc.symbolicAdd(vb, strValue);
                strAddress = m_SymCalc.symbolicAdd(strAddress, so.getValue());

                return strAddress;
            } else {
                throw new InvalidOperand("1574", objs_of_MemOperand);
            }
        } else {
            /* This operand is invalid, throw exeception */
            throw new InvalidOperand("1579", objs_of_MemOperand);
        }
    }

    /* override me if needs */
    private String getRegisterValue(String register) {
        String Reg = m_CPU.getRegisterFullName(register);
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

        assert (tmpSet != null);
        tmpSet.add(value);

        /* for debugging */
        System.out.println(String.format("674: @0x%x: %s = %s", inst_address, reg, value));

        /* Update register state */
        m_MachState.setRegValue(reg, value);

        return true;
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

        assert (tmpSet != null);
        tmpSet.add(value);

        /* for debuging */
        System.out.println(String.format("686: @0x%x: [%s] = %s", inst_address, address, value));

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
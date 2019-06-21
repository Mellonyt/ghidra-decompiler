import symbolicVSA.*;
import symbolicVSA.operand.*;

class InstructionDB implements Instruction {
    private Address m_addr;
    private String m_opcode;
    private Object[] m_objsrc;
    private Object[] m_objdst;

    public InstructionDB(long address, String opcode, Object[] source_oprand, Object[] dest_oprand) {
        m_addr = new Address(address);
        m_opcode = opcode;
        m_objsrc = source_oprand;
        m_objdst = dest_oprand;
    }

    public InstructionDB(long address, String opcode, Object[] oprand) {
        m_addr = new Address(address);
        m_opcode = opcode;
        m_objsrc = null;
        m_objdst = oprand;
    }

    public int getNumOperands() {
        int n = 0;

        if (m_objsrc != null && m_objsrc.length != 0)
            n++;
        if (m_objdst != null && m_objdst.length != 0)
            n++;

        return n;
    }

    /**
     * 0: unknow 1: Register 2: Scalar 3: GenericAddress 4: Address
     */
    public int getOperandType(int opIndex) {
        if (opIndex == 0) {
            if (m_objdst == null) {
                return 0; // Exception ?
            } else if (m_objdst.length == 1) {
                if (m_objdst[0] instanceof Register)
                    return 1;
                else if (m_objdst[0] instanceof Scalar)
                    return 2;
                else if (m_objdst[0] instanceof GenericAddress)
                    return 3;
                else
                    return 0;
            } else if (m_objdst.length > 1) {
                return 4;
            } else {
                return 0; // Exception ?
            }
        } else if (opIndex == 1) {
            if (m_objsrc == null) {
                return 0; // Exception ?
            } else if (m_objsrc.length == 1) {
                if (m_objsrc[0] instanceof Register)
                    return 1;
                else if (m_objsrc[0] instanceof Scalar)
                    return 2;
                else if (m_objsrc[0] instanceof GenericAddress)
                    return 3;
                else
                    return 0;
            } else if (m_objsrc.length > 1) {
                return 4;
            } else {
                return 0; // Exception ?
            }
        } else {
            return 0;
        }
    }

    public String getDefaultOperandRepresentation(int opIndex) {
        Object[] objs;

        if (opIndex == 0) {
            objs = m_objdst;
        } else if (opIndex == 1) {
            objs = m_objsrc;
        } else {
            objs = null;
        }

        String oprd = "";
        if (objs != null &&  objs.length > 0) {
            String[] arr = new String[objs.length];
            for (int i = 0; i < objs.length; i++) {
                arr[i] = objs[i].toString();
            }
            oprd = String.join(" ", arr);
        }
        return oprd;
    }

    public Object[] getOpObjects(int opIndex) {
        if (opIndex == 0)
            return m_objsrc;
        else if (opIndex == 1)
            return m_objsrc;
        else
            return null;
    }

    public String getMnemonicString() {
        return m_opcode;
    }

    public Address getAddress() {
        return m_addr;
    }

    public String toString() {
        int n = getNumOperands();

        if (n == 0) {
            return m_opcode;
        } else if (n == 1) {
            String dst = getDefaultOperandRepresentation(0);
            return String.format("%s %s", m_opcode, dst);
        } else if (n == 2) {
            String dst = getDefaultOperandRepresentation(0);
            String src = getDefaultOperandRepresentation(1);
            String oprds = String.join(",", dst, src);
            return String.format("%s %s", m_opcode, oprds);
        } else {
            return "";
        }
    }
}

class TestClass {

    private X86Interpreter inpt;

    TestClass() {
        inpt = X86Interpreter.getInterpreter();
    }

    public void doTest() {
        MachineState state = MachineState.createInitState(inpt.getCPU());
        System.out.println(state.toString());
        SMARTable smart = new SMARTable();

        /* create instruction: mov RAX, RBX */
        Register rax, rbx;
        Object[] oprd_rax;
        Object[] oprd_rbx;
        InstructionDB inst;


        rax = new Register("RAX");
        rbx = new Register("RBX");

        oprd_rax = new Object[] {rax};
        oprd_rbx = new Object[] {rbx};

        inst = new InstructionDB(0x80000L, "mov", oprd_rax, oprd_rbx);
        inpt.doRecording(state, smart, inst);

        inst = new InstructionDB(0x40000L, "push", oprd_rax);
        inpt.doRecording(state, smart, inst);
        inst = new InstructionDB(0x40001L, "pop", oprd_rax);
        inpt.doRecording(state, smart, inst);

        inst = new InstructionDB(0x40000L, "push", oprd_rbx);
        inpt.doRecording(state, smart, inst);
        inst = new InstructionDB(0x40001L, "pop", oprd_rbx);
        inpt.doRecording(state, smart, inst);

        inst = new InstructionDB(0x40001L, "sub", oprd_rax, oprd_rbx);
        inpt.doRecording(state, smart, inst);
        inst = new InstructionDB(0x40001L, "add", oprd_rax, oprd_rbx);
        inpt.doRecording(state, smart, inst);
    }
}

public class TestX86Interpreter {
    public static void main(String str[]) {

        TestClass test = new TestClass();
        test.doTest();
    }
}
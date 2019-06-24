import symbolicVSA.*;
import symbolicVSA.operand.*;

class InstructionDB implements Instruction {
    private Address m_Addr;
    private String m_opcode, m_strDst, m_strSrc;
    private Object[] m_objDst;
    private Object[] m_objSrc;

    public InstructionDB(long address, String opcode, String dst, Object[] dst_oprand, String src,
            Object[] src_oprand) {
        m_Addr = new Address(address);
        m_opcode = opcode;
        m_strDst = new String(dst);
        m_objDst = dst_oprand;
        m_strSrc = new String(src);
        m_objSrc = src_oprand;
    }

    public InstructionDB(long address, String opcode, String oprd, Object[] oprand) {
        m_Addr = new Address(address);
        m_opcode = opcode;
        m_strDst = oprd;
        m_objDst = oprand;
        m_strSrc = null;
        m_objSrc = null;

    }

    public int getNumOperands() {
        int n = 0;

        if (m_objSrc != null && m_objSrc.length != 0)
            n++;
        if (m_objDst != null && m_objDst.length != 0)
            n++;

        return n;
    }

    /**
     * 0: unknow 1: Register 2: Scalar 3: GenericAddress 4: Address
     */
    public int getOperandType(int opIndex) {
        if (opIndex == 0) {
            if (m_objDst == null) {
                return 0; // Exception ?
            } else if (m_objDst.length == 1) {
                if (m_objDst[0] instanceof Register)
                    return 1;
                else if (m_objDst[0] instanceof Scalar)
                    return 2;
                else if (m_objDst[0] instanceof GenericAddress)
                    return 3;
                else
                    return 0;
            } else if (m_objDst.length > 1) {
                return 4;
            } else {
                return 0; // Exception ?
            }
        } else if (opIndex == 1) {
            if (m_objSrc == null) {
                return 0; // Exception ?
            } else if (m_objSrc.length == 1) {
                if (m_objSrc[0] instanceof Register)
                    return 1;
                else if (m_objSrc[0] instanceof Scalar)
                    return 2;
                else if (m_objSrc[0] instanceof GenericAddress)
                    return 3;
                else
                    return 0;
            } else if (m_objSrc.length > 1) {
                return 4;
            } else {
                return 0; // Exception ?
            }
        } else {
            return 0;
        }
    }

    public String getDefaultOperandRepresentation(int opIndex) {
        if (opIndex == 0) {
            return m_strDst;
        } else if (opIndex == 1) {
            return m_strSrc;
        } else {
            return "";
        }
    }

    public Object[] getOpObjects(int opIndex) {
        if (opIndex == 0)
            return m_objDst;
        else if (opIndex == 1)
            return m_objSrc;
        else
            return null;
    }

    public String getMnemonicString() {
        return m_opcode;
    }

    public Address getAddress() {
        return m_Addr;
    }

    public String toString() {
        int n = getNumOperands();

        if (n == 0) {
            return m_opcode;
        } else if (n == 1) {
            return String.format("%s %s", m_opcode, m_strDst);
        } else if (n == 2) {
            String oprds = String.join(",", m_strDst, m_strSrc);
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
        // test1oprd();
        test2oprd();
        // test_si_oprand();
    }

    public void test1oprd() {
        MachineState state = MachineState.createInitState(inpt.getCPU());
        SMARTable smart = new SMARTable();

        /* create instruction: mov RAX, RBX */
        Register rax, rbx;
        Object[] oprd_rax;
        Object[] oprd_rbx;
        InstructionDB inst;

        rax = new Register("RAX");
        rbx = new Register("RBX");

        oprd_rax = new Object[] { rax };
        oprd_rbx = new Object[] { rbx };

        assert (state.getRegValue(rax.getName()).equals("VRAX"));
        assert (state.getRegValue(rbx.getName()).equals("VRBX"));

        inst = new InstructionDB(0x80000L, "mov", "RAX", oprd_rax, "RBX", oprd_rbx);
        inpt.doRecording(state, smart, inst);
        assert (state.getRegValue(rax.getName()).equals("VRBX"));

        inst = new InstructionDB(0x40000L, "push", "RAX", oprd_rax);
        inpt.doRecording(state, smart, inst);
        inst = new InstructionDB(0x40001L, "pop", "RAX", oprd_rax);
        inpt.doRecording(state, smart, inst);
        assert (state.getRegValue(rax.getName()).equals("VRBX"));

        inst = new InstructionDB(0x40000L, "push", "RBX", oprd_rbx);
        inpt.doRecording(state, smart, inst);
        inst = new InstructionDB(0x40001L, "pop", "RBX", oprd_rbx);
        inpt.doRecording(state, smart, inst);
        assert (state.getRegValue(rbx.getName()).equals("VRBX"));

        /* add more test-cases */
        System.out.println("Run test1oprd successfully");
    }

    public void test2oprd() {
        MachineState state = MachineState.createInitState(inpt.getCPU());
        SMARTable smart = new SMARTable();

        /* create instruction: mov RAX, RBX */
        Register rax, rbx, rdx, rbp;
        Object[] oprd_rax;
        Object[] oprd_rbx;
        Object[] oprd_rdx;
        Object[] oprd_rbp;
        Object[] oprd_mem;
        Object[] oprd_const;
        Scalar s0, s1;
        InstructionDB inst;

        rax = new Register("RAX");
        rbx = new Register("RBX");
        rdx = new Register("RDX");
        rbp = new Register("RBP");

        oprd_rax = new Object[] { rax };
        oprd_rbx = new Object[] { rbx };
        oprd_rdx = new Object[] { rdx };
        oprd_rbp = new Object[] { rbp };

        inst = new InstructionDB(0x40000L, "mov", "RAX", oprd_rax, "RBX", oprd_rbx);
        inpt.doRecording(state, smart, inst);
        inst = new InstructionDB(0x40001L, "sub", "RAX", oprd_rax, "RBX", oprd_rbx);
        inpt.doRecording(state, smart, inst);
        assert (state.getRegValue(rax.getName()).equals("0"));
        inst = new InstructionDB(0x40002L, "add", "RAX", oprd_rax, "RBX", oprd_rbx);
        inpt.doRecording(state, smart, inst);
        assert (state.getRegValue(rax.getName()).equals("VRBX"));

        /* MOV dword ptr [RBP + -0x64],0x0 */
        s0 = new Scalar(-0x64);
        s1 = new Scalar(0);
        oprd_mem = new Object[] { rbp, s0 };
        oprd_const = new Object[] { s1 };
        inst = new InstructionDB(0x400564L, "mov", "[RBP + -0x64]", oprd_mem, "0x0", oprd_const);
        inpt.doRecording(state, smart, inst);

        /* mov rax, [rax] */
        oprd_mem = new Object[] { rax };
        inst = new InstructionDB(0x400564L, "mov", "RAX", oprd_rax, "[RAX]", oprd_mem);
        inpt.doRecording(state, smart, inst);
        assert(state.getRegValue(rax.getName()).equals("VVRBX"));

        /* add more test-cases */
        System.out.println("Run test2oprd successfully");
    }

    public void test_si_oprand() {
        MachineState state = MachineState.createInitState(inpt.getCPU());
        SMARTable smart = new SMARTable();

        /* create instruction: mov RAX, RBX */
        Register rax, rbx, rbp, rdx;
        Object[] oprd_rax;
        Object[] oprd_rbx;
        Object[] oprd_rbp;
        Object[] oprd_rdx;
        Object[] oprd_mem;
        Object[] oprd_const;
        Scalar s0, s1;
        InstructionDB inst;

        rax = new Register("RAX");
        rdx = new Register("RDX");

        oprd_rax = new Object[] { rax };
        oprd_rdx = new Object[] { rdx };

        /* intializatoin: mov rax, 0x1 */
        s0 = new Scalar(1);
        oprd_const = new Object[] { s0 };
        inst = new InstructionDB(0x400568L, "mov", "RAX", oprd_rax, "0x1", oprd_const);
        inpt.doRecording(state, smart, inst);
        state.getRegValue(rax.getName());
        assert (state.getRegValue(rax.getName()).equals("1"));

        /* LEA RDX,[RAX*0x4] */
        s0 = new Scalar(4);
        oprd_rdx = new Object[] { rdx };
        oprd_mem = new Object[] { rax, s0 };
        inst = new InstructionDB(0x400568L, "lea", "RDX", oprd_rdx, "[RAX*0x4]", oprd_mem);
        inpt.doRecording(state, smart, inst);
        assert (state.getRegValue(rdx.getName()).equals("4"));

        /* add more test-cases */
        System.out.println("Run test_si_oprand successfully");
    }
}

public class TestX86Interpreter {
    public static void main(String str[]) {

        TestClass test = new TestClass();
        test.doTest();
    }
}
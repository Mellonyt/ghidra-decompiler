import symbolicVSA.*;


// interface AddressDB implements Address {
//     private long m_offset;
//     Address(long address) {
//         m_offset = address;
//     }

//     long getOffset() {
//         return m_offset;
//     }
// }

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

    public int getNumOperands() {
        int n = 0;

        if (m_objsrc.length != 0) n++;
        if (m_objdst.length != 0) n++;

        return n;
    }
    
   
    public int getOperandType(int opIndex) {
        return 0;
    }
    

    public String getDefaultOperandRepresentation(int opIndex){
        return "";
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
    
}


private class TestClass {

    private SymbolicCalculator calc;

    TestClass() {
        calc = SymbolicCalculator.getCalculator();
    }

    public void doTest() {

    }
}

public class TestX86Interpreter {
    public static void main(String str[]) {

        TestClass test = new TestClass();
        test.doTest();
    }
}
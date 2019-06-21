package symbolicVSA;

import java.util.*;


public class X86Processor {

    private static final String[] m_Regs64 = { "RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "RBP", "RSP", "R8", "R9",
            "R10", "R11", "R12", "R13", "R14", "R15" };
    private static final String[] m_Regs32 = { "EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP", "R8D", "R9D",
            "R10D", "R11D", "R12D", "R13D", "R14D", "R15D" };
    private static final String[] m_Regs16 = { "AX", "BX", "CX", "DX", "DI", "SI", "BP", "SP" };
    private static final String[] m_Regs8h = { "AH", "BH", "CH", "DH" };
    private static final String[] m_Regs8l = { "AL", "BL", "CL", "DL" };
    private static final String[] m_RegSeg = { "FS", "GS" };
    private static final String[] m_RegXmm = { "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7" };

    private static Map<String, String> m_RegMap;
    private static String[] m_AllRegs;

    private static X86Processor m_singleton = null;

    private X86Processor() {
        createRegNameMapping();
        collectAllRegisters();
    }

    public static X86Processor getProcessor() {
        if (m_singleton == null) {
            m_singleton = new X86Processor();
        }
        return m_singleton;
    }

    /**
     * Create name mapping for register names
     */
    private void createRegNameMapping() {
        if (m_RegMap == null) {
            m_RegMap = new HashMap<>();
        }

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
    }

    /**
     * Collect all available registers
     */
    private void collectAllRegisters() {
        if (m_AllRegs == null) {
            m_AllRegs = new String[m_RegSeg.length + m_RegXmm.length + m_Regs64.length];
        }

        String[] allRegs = m_AllRegs;
        System.arraycopy(m_RegSeg, 0, allRegs, 0, m_RegSeg.length);
        System.arraycopy(m_RegXmm, 0, allRegs, m_RegSeg.length, m_RegXmm.length);
        System.arraycopy(m_Regs64, 0, allRegs, m_RegSeg.length + m_RegXmm.length, m_Regs64.length);
        m_AllRegs = allRegs;
    }

    /* get the name of whole width register */
    public String getRegisterFullName(String register) {
        return m_RegMap.get(register);
    }

    /* Get all available registers on this architecture */
    public String[] getAllRegisters() {
        return m_AllRegs;
    }
}


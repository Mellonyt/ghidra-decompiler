package symbolicVSA;

import java.util.*;

import symbolicVSA.*;

/* Machine state: A simple machine mode consist with only registers and memory */
public class MachineState {
    private Map<String, String> m_regs;
    private Map<String, String> m_mems;

    public MachineState(Map<String, String> register_status, Map<String, String> memory_status) {
        m_regs = register_status;
        m_mems = memory_status;
    }

    /* Used for forking */
    private MachineState() {

    }

    public static MachineState createInitState(X86Processor cpu) {
        MachineState s = new MachineState();

        /* Set register values to symbolic initial values */
        s.m_regs = new HashMap<>();        // CPU State : Registers
        s.m_mems = new HashMap<>();        // CPU State : Memory slot

        String[] allRegs = cpu.getAllRegisters();

        for (String reg: allRegs) {
            s.m_regs.put(reg, "V" + reg);
        }

        /* Doesn't need to initialize memory state */
        return s;
    }

    /* override me if needs */
    public void setRegValue(String register, String value) {
        m_regs.put(register, value);
    }

    /* override me if needs */
    public String getRegValue(String register) {
        return m_regs.get(register);
    }

    /* override me if needs */
    public void setMemValue(String address, String value) {
        m_mems.put(address, value);
    }

    /* override me if needs */
    public String getMemValue(String address) {
        return touchMemAddr(address);
    }

    /**
     * Make the memory address as never untouched
     * 
     * @param address
     * @return
     */
    public String touchMemAddr(String address) {
        String value = m_mems.get(address);
        if (value == null) {
            String symbol;

            if (address.indexOf(' ') != -1) {
                symbol = String.format("V(%s)", address.replaceAll("\\s+", ""));
            } else {
                symbol = "V" + address;
            }

            m_mems.put(address, symbol);            
            return symbol;
        }
        else {
            return value;
        }
    }

    /**
     * Make the memory address as never untouched
     * 
     * @param address
     * @return
     */
    public void untouchMemAddr(String address) {
        m_mems.remove(address);
    }

    /**
     * Fork a Machine state to caller
     *
     * @param state
     * @param reuse
     */
    public MachineState forkState() {
        MachineState s = new MachineState();
        s.m_regs = _deepCopy(m_regs);
        s.m_mems = _deepCopy(m_mems);

        return s;
    }

    /**
     * Make a deep copy of a Map, for internal use only
     *
     * @param proto
     * @return
     */
    private Map<String, String> _deepCopy(Map<String, String> proto) {
        Map<String, String> to = new HashMap<>();

        for (Map.Entry<String, String> ent : proto.entrySet()) {
            String k = new String(ent.getKey());
            String v = new String(ent.getValue());
            to.put(k, v);
        }
        return to;
    }

    public String toString() {
        return String.format("%s %s", m_regs.toString(), m_mems.toString());
    }
}

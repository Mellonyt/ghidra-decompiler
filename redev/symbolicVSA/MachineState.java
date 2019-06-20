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

    /* override me if needs */
    public String getRegValue(String register) {
        return m_regs.get(register);
    }

    /* override me if needs */
    public String getMemValue(String address) {
        return m_mems.get(address);
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
}

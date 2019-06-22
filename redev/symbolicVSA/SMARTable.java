package symbolicVSA;

import java.io.IOException;
import java.util.*; // Map & List
import java.util.Arrays;

import symbolicVSA.SymbolicCalculator;

/**
 * SMARTable, wrap a VSA table for each code-line. Can be used as Map
 */
public class SMARTable {
    private static final String VINF = "VINF";
    private static int WIDENVS_THRESHOLD = 5; // tigger widening
    private SymbolicCalculator m_calc;

    public Map<Long, Map<String, Set<String>>> m_tbl;

    public SMARTable() {
        m_calc = SymbolicCalculator.getCalculator();
        m_tbl = new HashMap<>();
    }

    public int size() {
        return m_tbl.size();
    }

    public void clear() {
        m_tbl.clear();
    }

    /**
     * Put new mapVS into table. The same line of code may access other memory
     * 
     * @param key
     * @param value
     */
    public void putDeep(Long key, Map<String, Set<String>> value) {
        /* The same line of code may access other memory */
        Map<String, Set<String>> mapVS = m_tbl.get(key);

        if (mapVS == null) {
            m_tbl.put(key, value);
        } else {
            mapVS.putAll(value);
        }
    }

    /* Interface for compatible with Map */
    public void put(Long key, Map<String, Set<String>> value) {
        putDeep(key, value);
    }

    /* Interface for compatible with Map */
    public Map<String, Set<String>> get(Long key) {
        return m_tbl.get(key);
    }

    /**
     * Use symbolic value VINF to widen value-set We do widening just for Equal
     * difference series
     * 
     * @param final_set
     * @param new_set
     * @return
     */
    private boolean widenVS(Set<String> final_set, Set<String> new_set) {
        /* Already widened to VINF */
        if (final_set.contains("VINF"))
            return false;

        /* Union new_set before widening */
        final_set.addAll(new_set);

        /* do widening if it has more than WIDENVS_THRESHOLD values */
        if (final_set.size() < WIDENVS_THRESHOLD)
            return false;

        /* do windenging for Equal difference series */
        int nLen = final_set.size();
        String vs[] = final_set.toArray(new String[nLen]);
        long pt[] = new long[nLen - 1];
        boolean bWidening = true;

        for (int i = 0; i < nLen - 1; i++) {
            String s = m_calc.symbolicSub(vs[i + 1], vs[i]);
            if (m_calc.isPureDigital(s)) {
                pt[i] = Long.decode(s);
            } else {
                bWidening = false;
                break;
            }
        }

        if (!bWidening)
            return false;

        /* Equal difference series ? */
        boolean bSeries = true;
        Arrays.sort(pt);
        for (int i = 1; bSeries && (i < pt.length); i++) {
            bSeries = (pt[i] == pt[i - 1]);
        }

        /* Do widening */
        if (bSeries)
            final_set.add(new String(VINF));

        return true;
    }

    /**
     * Test if final_set contains all elements from new_set, considering windening
     *
     * @param final_set
     * @param new_set
     * @return
     */
    private boolean containVS(Set<String> final_set, Set<String> new_set) {
        if (final_set.containsAll(new_set)) {
            return true;
        } else if (final_set.contains("VINF")) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Test if containing-relationship between two SMAR-Tables
     * 
     * @param new_smar_table
     * @return
     */
    public boolean containsAll(Map<Long, Map<String, Set<String>>> new_smar_table) {
        if (m_tbl.entrySet().containsAll(new_smar_table.entrySet())) {
            return true;
        }

        /* test if is widened? */
        boolean bContain;

        for (Map.Entry<Long, Map<String, Set<String>>> entNewSMARTbl : new_smar_table.entrySet()) {
            Long nNewLineno = entNewSMARTbl.getKey();
            Map<String, Set<String>> mapOldVSTble = m_tbl.get(nNewLineno);

            /* A new line of code is executed */
            if (mapOldVSTble == null)
                return false;

            /* Test if all values exist */
            Map<String, Set<String>> mapNewVSTble = entNewSMARTbl.getValue();
            for (Map.Entry<String, Set<String>> entNewVSTble : mapNewVSTble.entrySet()) {
                String strNewAddr = entNewVSTble.getKey();
                Set<String> setOldVS = mapOldVSTble.get(strNewAddr);

                /**
                 * The same line of code may may access another memory addrss, looping to access
                 * an array e.g. loop mov [rbp + rax], 0x10
                 */
                if (setOldVS == null)
                    continue;

                bContain = containVS(setOldVS, entNewVSTble.getValue());

                if (!bContain)
                    return false;
            }
        }
        return true;
    }

    /**
     * Test if containing-relationship between two SMAR-Tables
     * 
     * @param new_smar_table
     * @return
     */
    public boolean containsAll(SMARTable new_smar_table) {
        return containsAll(new_smar_table.m_tbl);
    }

    /**
     * Put all values from new_smar_table into m_tbl
     * 
     * @param new_smar_table
     */
    public void putAll(Map<Long, Map<String, Set<String>>> new_smar_table) {

        for (Map.Entry<Long, Map<String, Set<String>>> entNewSMARTbl : new_smar_table.entrySet()) {
            Long nNewLineno = entNewSMARTbl.getKey();
            Map<String, Set<String>> mapOldVSTble = m_tbl.get(nNewLineno);

            /* add all records from executing a new line of code */
            if (mapOldVSTble == null) {
                m_tbl.put(nNewLineno, entNewSMARTbl.getValue());
                continue;
            }

            /* Test if all values exist */
            Map<String, Set<String>> mapNewVSTble = entNewSMARTbl.getValue();
            for (Map.Entry<String, Set<String>> entNewVSTble : mapNewVSTble.entrySet()) {
                String strNewAddr = entNewVSTble.getKey();
                Set<String> setOldVS = mapOldVSTble.get(strNewAddr);

                if (setOldVS == null) {
                    mapOldVSTble.put(strNewAddr, entNewVSTble.getValue());
                } else {
                    widenVS(setOldVS, entNewVSTble.getValue());
                }
            }
        }
    }

    /**
     * Put all values from new_smar_table into m_tbl
     * 
     * @param new_smar_table
     */
    public void putAll(SMARTable new_smar_table) {
        Map<Long, Map<String, Set<String>>> mapNewSMARTbl = new_smar_table.m_tbl;
        putAll(mapNewSMARTbl);
    }
}

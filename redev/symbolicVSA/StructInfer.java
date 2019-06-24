package symbolicVSA;

import java.util.*;

import javax.print.DocFlavor.STRING;

import com.sun.source.tree.Scope;

import symbolicVSA.*;

public class StructInfer {
    private SymbolicCalculator m_calc;

    public StructInfer() {
        m_calc = SymbolicCalculator.getCalculator();
    }

    /**
     * Find out all scopes: each pure symbolic value representing a new scope
     * 
     * @param mapSMAT
     * @return
     */
    public Set<Map<String, List<Long>>> findPossibleArrayAccess(
            Map<Long, Map<String, Set<String>>> symbolic_memory_access_table) {
        Set<Map<String, List<Long>>> setArrayAccess = new HashSet<>();
        Map<String, List<Long>> mapArrayAccess;
        List<Long> listVS;
        String scope, addr;

        for (Map.Entry<Long, Map<String, Set<String>>> entMapSMAT : symbolic_memory_access_table.entrySet()) {
            Map<String, Set<String>> mapVS = entMapSMAT.getValue();
            /* WIDENING_THRESHOLD == 4, so it should hava size bigger than or equal to 4 */
            if (mapVS.size() < 4)
                continue;

            /* Get a list of accessed memory address by this line of code */
            List<String> listAddr = new ArrayList<>(mapVS.keySet());

            /* Test if this is a Scope ? */
            addr = listAddr.get(0);
            if (addr.length() < 1 || addr.charAt(0) != 'V')
                continue;

            /* Get the scope name */
            scope = addr.split(" ", 0)[0];

            /* Al memory addresses are in the same scope ? */
            boolean bSameScope = true;
            String delta;

            listVS = new ArrayList<>();
            for (int i = 0; i < listAddr.size(); i++) {
                delta = m_calc.symbolicSub(listAddr.get(i), scope);
                if (!m_calc.isPureDigital(delta)) {
                    bSameScope = false;
                    break;
                } else {
                    Long v = Long.decode(delta);
                    if (listVS.contains(v))
                        continue;
                    listVS.add(v);
                }
            }

            if (!bSameScope)
                continue;

            /* Now, we find a possible array accessing pattern */
            mapArrayAccess = new HashMap<>();
            Collections.sort(listVS);
            mapArrayAccess.put(scope, listVS);

            setArrayAccess.add(mapArrayAccess);
        }

        /* sort all data in asending order */
        for (Map<String, List<Long>> mapAccess : setArrayAccess) {
            for (Map.Entry<String, List<Long>> entMapAccess : mapAccess.entrySet()) {
                Collections.sort(entMapAccess.getValue());
            }
        }

        return setArrayAccess;
    }

    /**
     * Find out all scopes: each pure symbolic value representing a new scope
     * 
     * @param mapSMAT
     * @return
     */
    public Map<String, List<Long>> findMemoryScopesWOArray(
            Map<Long, Map<String, Set<String>>> symbolic_memory_access_table) {
        Map<String, List<Long>> mapScopeAccess = new HashMap<>();
        List<Long> addrSet;
        String scope;

        for (Map.Entry<Long, Map<String, Set<String>>> entMapSMAT : symbolic_memory_access_table.entrySet()) {
            Map<String, Set<String>> mapVS = entMapSMAT.getValue();

            if (mapVS.size() > 2) // ignore array access, at most one register and one memory operand
                continue;

            /* all memory addresses accessed by instructions */
            for (Map.Entry<String, Set<String>> entMapVS : mapVS.entrySet()) {
                String addr = entMapVS.getKey();
                assert (addr.length() > 0);
                if (addr.charAt(0) != 'V')
                    continue;

                /* Get the scope name */
                scope = addr.split(" ", 0)[0];

                /* Create a List<Long> at the first time of adding this scope */
                addrSet = mapScopeAccess.get(scope);
                if (addrSet == null) {
                    addrSet = new ArrayList<>();
                    mapScopeAccess.put(scope, addrSet);
                }

                /* The address may be: VRSP + VRAX + 100, so we need further verification */
                String delta = m_calc.symbolicSub(addr, scope);
                if (!m_calc.isPureDigital(delta))
                    continue;

                Long v = Long.decode(delta);
                if (!addrSet.contains(v)) {
                    addrSet.add(v);
                }
            }
        }

        /* sorting all data in asending order */
        for (Map.Entry<String, List<Long>> entMapScope : mapScopeAccess.entrySet()) {
            Collections.sort(entMapScope.getValue());
        }
        return mapScopeAccess;
    }

    /**
     * An array can be on local stack or passed in as a prameter
     * 
     * @param possible_array_scope
     * @param all_memory_scopes
     * @return
     */
    public Set<String> inferArray(Set<Map<String, List<Long>>> possible_array_scope,
            Map<String, List<Long>> all_memory_scopes) {
        Set<String> arrInfo = new HashSet<>();

        for (Map<String, List<Long>> mapArrayAccess : possible_array_scope) {
            List<Long> listArrayOffset = new ArrayList<>();
            String scope = "";

            for (Map.Entry<String, List<Long>> entArrayAccess : mapArrayAccess.entrySet()) {
                scope = entArrayAccess.getKey();
                listArrayOffset = entArrayAccess.getValue();
                break; // Should have only one elment
            }

            // Collections.sort(listArrayOffset);
            long maxAddr = (long) Collections.max(listArrayOffset);
            long minAddr = (long) Collections.min(listArrayOffset); // Base-addrss => Scope + minAddr
            long stride = (long) listArrayOffset.get(1) - (long) listArrayOffset.get(0); // Stride

            /* Calculate up-bound */
            List<Long> listScopeVS = all_memory_scopes.get(scope);
            long upbound = maxAddr + stride;

            /* find max lowerbound if */
            if (listScopeVS != null) {
                // Collections.sort(listScopeVS); // in asending order
                for (Long v : listScopeVS) {
                    if (v > maxAddr) {
                        upbound = v;
                        break;
                    }
                }
            }

            /* For debuging */
            String base = (minAddr == 0) ? scope : String.format("%s%d", scope, minAddr);
            String msg = String.format("Base: %s, stride: %d: size in bytes: %d", base, stride, upbound - minAddr);

            arrInfo.add(msg);
        }

        return arrInfo;
    }

    /**
     * We identify struct instance passed in as a prameter.
     * 
     * @param all_memory_scopes
     * @return
     */
    public Map<String, List<Long>> inferStruct(Map<String, List<Long>> all_memory_scopes) {
        /* Get all scopes except stack, each scope has at most one strcuture */
        Map<String, List<Long>> mapStruct = new HashMap<>();
        List<Long> listOffset;
        String scope;

        for (Map.Entry<String, List<Long>> entScopeAccess : all_memory_scopes.entrySet()) {
            scope = entScopeAccess.getKey();

            if (scope.equals("VRSP"))
                continue;

            listOffset = entScopeAccess.getValue();
            /* Each scope should have to access at leat two memory elments */
            if (listOffset.size() < 2)
                continue;

            /* Each scope is treated as having a structure */
            mapStruct.put(scope, listOffset);
        }

        return mapStruct;
    }
}

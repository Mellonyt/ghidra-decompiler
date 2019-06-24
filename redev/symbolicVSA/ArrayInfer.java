package symbolicVSA;

import java.util.*;

import com.sun.source.tree.Scope;

import symbolicVSA.*;

public class ArrayInfer {
    private SymbolicCalculator m_calc;

    public ArrayInfer() {
        m_calc = SymbolicCalculator.getCalculator();
    }

    /**
     * Find out all scopes: each pure symbolic value representing a new scope
     * 
     * @param mapSMAT
     * @return
     */
    public Set<Map<String, List<Long>>> findArrayAccess(Map<Long, Map<String, Set<String>>> mapSMAT) {
        Set<Map<String, List<Long>>> setArrayAccess = new HashSet<>();
        Map<String, List<Long>> mapArrayAccess;
        List<Long> listVS;
        String scope, addr;

        for (Map.Entry<Long, Map<String, Set<String>>> entMapSMAT : mapSMAT.entrySet()) {
            Map<String, Set<String>> mapVS = entMapSMAT.getValue();
            /* WIDENING_THRESHOLD == 4 */
            if (mapVS.size() < 4)
                continue;

            List<String> listAddr = new ArrayList<>(mapVS.keySet());
            assert (listAddr.size() > 0);

            /* Test if in a Scope ? */
            addr = listAddr.get(0);
            if (addr.length() < 1 || addr.charAt(0) != 'V')
                continue;
            /* Get the scope name */
            scope = addr.split(" ", 0)[0];

            /* In the same scope ? */
            boolean bSameScope = true;
            listVS = new ArrayList<>();
            for (int i = 0; i < listAddr.size(); i++) {
                String delta = m_calc.symbolicSub(listAddr.get(i), scope);
                if (!m_calc.isPureDigital(delta)) {
                    bSameScope = false;
                    break;
                } else {
                    listVS.add(Long.decode(delta));
                }
            }
            if (!bSameScope)
                continue;

            /* Find an array access */
            mapArrayAccess = new HashMap<>();
            Collections.sort(listVS);
            mapArrayAccess.put(scope, listVS);
            setArrayAccess.add(mapArrayAccess);
        }

        return setArrayAccess;
    }

    /**
     * Find out all scopes: each pure symbolic value representing a new scope
     * 
     * @param mapSMAT
     * @return
     */
    public Map<String, List<Long>> findScopeAccesssWOArray(Map<Long, Map<String, Set<String>>> mapSMAT) {
        Map<String, List<Long>> mapScopeAccess = null;
        List<Long> addrSet;
        String scope;

        for (Map.Entry<Long, Map<String, Set<String>>> entMapSMAT : mapSMAT.entrySet()) {
            Map<String, Set<String>> mapVS = entMapSMAT.getValue();

            if (mapVS.size() > 2)
                continue; // ignore array access, at most one register and one memory operand

            /* all stack address accessed by other instructions */
            for (Map.Entry<String, Set<String>> entMapVS : mapVS.entrySet()) {
                String addr = entMapVS.getKey();
                assert (addr.length() > 0);
                if (addr.charAt(0) != 'V')
                    continue;

                /* Get scope name */
                scope = addr.split(" ", 0)[0];

                if (mapScopeAccess == null) {
                    mapScopeAccess = new HashMap<>();
                }
                addrSet = mapScopeAccess.get(scope);
                if (addrSet == null) {
                    addrSet = new ArrayList<>();
                    mapScopeAccess.put(scope, addrSet);
                }

                /* The address may be: VRSP + VRAX + 100, so we need further verification */
                String delta = m_calc.symbolicSub(addr, scope);
                if (!m_calc.isPureDigital(delta))
                    continue;

                addrSet.add(Long.decode(delta));
                Collections.sort(addrSet);
            }
        }
        return mapScopeAccess;
    }

    public Set<String> inferArray(Set<Map<String, List<Long>>> setArrayAccess, Map<String, List<Long>> mapScopeAccess) {
        Set<String> arrInfo = new HashSet<>();

        for (Map<String, List<Long>> mapArrayAccess : setArrayAccess) {
            List<Long> listArrOffset = new ArrayList<>();
            String scope = "";

            for (Map.Entry<String, List<Long>> entArrayAccess : mapArrayAccess.entrySet()) {
                scope = entArrayAccess.getKey();
                listArrOffset = entArrayAccess.getValue();
                break; // Should have only one elment
            }

            // Collections.sort(listArrOffset);
            long maxAddr = (long) Collections.max(listArrOffset);
            long minAddr = (long) Collections.min(listArrOffset); // Base-addrss => Scope + minAddr
            long stride = (long) listArrOffset.get(1) - (long) listArrOffset.get(0); // Stride

            /* Calculate up-bound */
            long upbound = maxAddr;
            List<Long> listScopeVS = mapScopeAccess.get(scope);

            if (listScopeVS == null) {
                upbound = maxAddr;
            } else {
                /* find max lowerbound */
                // Collections.sort(listScopeVS); // in asending order
                for (Long v : listScopeVS) {
                    if (v > maxAddr) {
                        upbound = v;
                        break;
                    }
                }
            }

            /* For debuging */
            String msg = String.format("Base: %s%d, stide: %d: size in bytes: %d", scope, minAddr, stride,
                    upbound - minAddr);
            arrInfo.add(msg);
        }

        return arrInfo;
    }
}

import java.util.*;

import symbolicVSA.*;

class TestClass {

    private SMARTable table;
    SymbolicCalculator calc;

    TestClass() {
        table = new SMARTable();
        calc = SymbolicCalculator.getCalculator();
    }

    public void doTest() {
        Map<Long, Map<String, Set<String>>> mapSMAT;
        Map<String, Set<String>> mapVS;
        Set<String> setVS;

        /**
         * int main (int argc, char *argv[]) { int arr[20]; int i; for (i = 0; i < 20;
         * i++) { arr[i] = i; } return 0; }
         */

        /**
         * 0x400546 = {VRSP -8=[VRBP], RSP=[VRSP -8]} -------del----- 0x400547 =
         * {RBP=[VRSP -8]} -------del----- 0x40054a = {RSP=[VRSP -136]} 0x40054e = {VRSP
         * -124=[VRDI]} 0x400551 = {VRSP -136=[VRSI]} 0x400555 = {VFS +40=[V(VFS+40)],
         * RAX=[V(VFS+40)]} -------del----- 0x40055e = {VRSP -16=[V(VFS+40)]} 0x400562 =
         * {RAX=[0]} 0x400564 = {VRSP -108=[0]} 0x40056d = {RAX=[0, 1, 2, 3, VINF], VRSP
         * -108=[0, 1, 2, 3, VINF]} 0x400572 = {RDX=[0, 1, 2, 3, VINF], VRSP -108=[0, 1,
         * 2, 3, VINF]} 0x400575 = {VRSP -104=[0], VRSP -92=[3], VRSP -100=[1], VRSP
         * -96=[2]} 0x400579 = {VRSP -108=[1, 2, 3, VINF, 4]} 0x40057d = {VRSP -108=[0,
         * 1, 2, 3, VINF]} 0x400583 = {RAX=[0x0]} -------del----- 0x400588 =
         * {RCX=[V(VFS+40)], VRSP -16=[V(VFS+40)]} -------del----- 0x40058c = {VFS
         * +40=[V(VFS+40)], RCX=[0]} -------del----- 0x40059c = {RBP=[VRBP], RSP=[VRSP,
         * VRSP -8]} -------del----- 0x40059d = {RSP=[VRSP +8]} -------del-----
         */

        mapSMAT = new HashMap<>();
        /* 0x40054a = {RSP=[VRSP -136]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRSP -136"));
        mapVS.put("RSP", setVS);
        mapSMAT.put(0x40054aL, mapVS);

        /* 0x40054e = {VRSP -124=[VRDI]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRDI"));
        mapVS.put("VRSP -124", setVS);
        mapSMAT.put(0x40054eL, mapVS);

        /* 0x400551 = {VRSP -136=[VRSI]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRSI"));
        mapVS.put("VRSP -136", setVS);
        mapSMAT.put(0x400551L, mapVS);

        /* 0x40055e = {VRSP -16=[V(VFS+40)]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("V(VFS+40)"));
        mapVS.put("VRSP -16", setVS);
        mapSMAT.put(0x40055eL, mapVS);

        /* 0x400562 = {RAX=[0]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("0"));
        mapVS.put("RAX", setVS);
        mapSMAT.put(0x400562L, mapVS);

        /* 0x400564 = {VRSP -108=[0]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("0"));
        mapVS.put("VRSP -108", setVS);
        mapSMAT.put(0x400564L, mapVS);

        /* 0x40056d = {RAX=[0, 1, 2, 3, VINF], VRSP -108=[0, 1, 2, 3, VINF]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
        mapVS.put("RAX", setVS);
        setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
        mapVS.put("VRSP -108", setVS);
        mapSMAT.put(0x40056dL, mapVS);

        /* 0x400575 = {VRSP -104=[0], VRSP -92=[3], VRSP -100=[1], VRSP -96=[2]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("0"));
        mapVS.put("VRSP -104", setVS);
        setVS = new HashSet<>(Arrays.asList("3"));
        mapVS.put("VRSP -92", setVS);
        setVS = new HashSet<>(Arrays.asList("1"));
        mapVS.put("VRSP -100", setVS);
        setVS = new HashSet<>(Arrays.asList("2"));
        mapVS.put("VRSP -96", setVS);
        mapSMAT.put(0x400575L, mapVS);

        /* 0x400579 = {VRSP -108=[1, 2, 3, VINF, 4]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("1", "2", "3", "VINF", "4"));
        mapVS.put("VRSP -108", setVS);
        mapSMAT.put(0x400579L, mapVS);

        /* 0x40057d = {VRSP -108=[0, 1, 2, 3, VINF]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
        mapVS.put("VRSP -108", setVS);
        mapSMAT.put(0x40057dL, mapVS);

        List arrIdx = new ArrayList();
        long minaddr = 0;

        Set<String> nonaddridxset = new HashSet<>();

        for (Map.Entry<Long, Map<String, Set<String>>> entMapSMAT : mapSMAT.entrySet()) {
            Long l = entMapSMAT.getKey();
            mapVS = entMapSMAT.getValue();
            if (mapVS.size() < 3) { // WIDENING_THRESHOLD == 4
                /* all stack address accessed by other instructions */
                for (Map.Entry<String, Set<String>> entMapVS : mapVS.entrySet()) {
                    String addr = entMapVS.getKey();
                    if (!addr.contains("VRSP")) {
                        /* On stack address space ? */
                        continue;
                    } else {
                        nonaddridxset.add(addr);
                    }
                }

                continue;
            }

            arrIdx.clear();
            System.out.println(mapVS.toString());
            for (Map.Entry<String, Set<String>> entMapVS : mapVS.entrySet()) {
                String addr = entMapVS.getKey();
                if (!addr.contains("VRSP")) {
                    /* On stack address space ? */
                    break;
                }

                /* Stack memory access */
                String delta = calc.symbolicSub("VRSP", addr);
                if (!calc.isPureDigital(delta)) {
                    break;
                }

                String msg = String.format("Access stack array: VRSP-%d", Long.decode(delta));
                System.out.println(msg);

                arrIdx.add(Long.decode(delta));

            }
            if (arrIdx.size() > 0) {
                Collections.sort(arrIdx);
                System.out.println(arrIdx.toString());

                long max = (long) Collections.max(arrIdx);
                minaddr = (long) Collections.min(arrIdx);
                String msg = String.format("Array base address: VRSP-%d", max);
                System.out.println(msg);

                long stride = (long) arrIdx.get(1) - (long) arrIdx.get(0);
                msg = String.format("Array stride is: %d", stride);
                System.out.println(msg);

            }

        }

        List nonarrIdx = new ArrayList();

        for (String addr : nonaddridxset) {
            /* Stack memory access */
            String delta = calc.symbolicSub("VRSP", addr);
            if (!calc.isPureDigital(delta)) {
                break;
            } else {
                nonarrIdx.add(Long.decode(delta));
            }
        }
        Collections.sort(nonarrIdx);

        /* find max lowerbound */
        long value = 0;
        for (int i = 0; i < nonarrIdx.size(); i++) {
            if ((long) nonarrIdx.get(i) < minaddr) {
                value = (long) nonarrIdx.get(i);
            }
        }

        String msg = String.format("Array lowbound is: %d", value);
        System.out.println(msg);

        // System.out.println(mapSMAT.toString());
        System.out.println("Run doTest successfully");
    }
}

public class TestArrayInfer {

    public static void main(String[] args) {
        TestClass test = new TestClass();
        test.doTest();
    }
}
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
         * 0x400546 = {VRSP -8=[VRBP], RSP=[VRSP -8]} -------ignore----- 0x400547 =
         * {RBP=[VRSP -8]} -------ignore----- 0x40054a = {RSP=[VRSP -136]} 0x40054e = {VRSP
         * -124=[VRDI]} 0x400551 = {VRSP -136=[VRSI]} 0x400555 = {VFS +40=[V(VFS+40)],
         * RAX=[V(VFS+40)]} -------ignore----- 0x40055e = {VRSP -16=[V(VFS+40)]} 0x400562 =
         * {RAX=[0]} 0x400564 = {VRSP -108=[0]} 0x40056d = {RAX=[0, 1, 2, 3, VINF], VRSP
         * -108=[0, 1, 2, 3, VINF]} 0x400572 = {RDX=[0, 1, 2, 3, VINF], VRSP -108=[0, 1,
         * 2, 3, VINF]} 0x400575 = {VRSP -104=[0], VRSP -92=[3], VRSP -100=[1], VRSP
         * -96=[2]} 0x400579 = {VRSP -108=[1, 2, 3, VINF, 4]} 0x40057d = {VRSP -108=[0,
         * 1, 2, 3, VINF]} 0x400583 = {RAX=[0x0]} -------ignore----- 0x400588 =
         * {RCX=[V(VFS+40)], VRSP -16=[V(VFS+40)]} -------ignore----- 0x40058c = {VFS
         * +40=[V(VFS+40)], RCX=[0]} -------ignore----- 0x40059c = {RBP=[VRBP], RSP=[VRSP,
         * VRSP -8]} -------ignore----- 0x40059d = {RSP=[VRSP +8]} -------ignore-----
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

        ArrayInfer infer = new ArrayInfer();
        Set<Map<String, List<Long>>> arrayAccess = infer.findArrayAccess(mapSMAT);

        System.out.println(arrayAccess.toString());

        Map<String, List<Long>> scopeAccess = infer.findScopeAccesssWOArray(mapSMAT);

        System.out.println(scopeAccess.toString());
         

    }
}

public class TestArrayInfer {

    public static void main(String[] args) {
        TestClass test = new TestClass();
        test.doTest();
    }
}
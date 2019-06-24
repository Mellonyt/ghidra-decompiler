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
        // identifyLoop1();
        identifyLoop2();
    }

    public void identifyLoop1() {
        Map<Long, Map<String, Set<String>>> mapSMAT;
        Map<String, Set<String>> mapVS;
        Set<String> setVS;

        /**
         * int main (int argc, char *argv[]) { int arr[20]; int i; for (i = 0; i < 20;
         * i++) { arr[i] = i; } return 0; }
         */

        /**
         * 0x400546 = {VRSP -8=[VRBP], RSP=[VRSP -8]} -------ignore----- 0x400547 =
         * {RBP=[VRSP -8]} -------ignore----- 0x40054a = {RSP=[VRSP -136]} 0x40054e =
         * {VRSP -124=[VRDI]} 0x400551 = {VRSP -136=[VRSI]} 0x400555 = {VFS
         * +40=[V(VFS+40)], RAX=[V(VFS+40)]} -------ignore----- 0x40055e = {VRSP
         * -16=[V(VFS+40)]} 0x400562 = {RAX=[0]} 0x400564 = {VRSP -108=[0]} 0x40056d =
         * {RAX=[0, 1, 2, 3, VINF], VRSP -108=[0, 1, 2, 3, VINF]} 0x400572 = {RDX=[0, 1,
         * 2, 3, VINF], VRSP -108=[0, 1, 2, 3, VINF]} 0x400575 = {VRSP -104=[0], VRSP
         * -92=[3], VRSP -100=[1], VRSP -96=[2]} 0x400579 = {VRSP -108=[1, 2, 3, VINF,
         * 4]} 0x40057d = {VRSP -108=[0, 1, 2, 3, VINF]} 0x400583 = {RAX=[0x0]}
         * -------ignore----- 0x400588 = {RCX=[V(VFS+40)], VRSP -16=[V(VFS+40)]}
         * -------ignore----- 0x40058c = {VFS +40=[V(VFS+40)], RCX=[0]}
         * -------ignore----- 0x40059c = {RBP=[VRBP], RSP=[VRSP, VRSP -8]}
         * -------ignore----- 0x40059d = {RSP=[VRSP +8]} -------ignore-----
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

        Set<String> info = infer.inferArray(arrayAccess, scopeAccess);
        for (String msg : info) {
            System.out.println(msg);
        }
    }

    public void identifyLoop2() {
        Map<Long, Map<String, Set<String>>> mapSMAT;
        Map<String, Set<String>> mapVS;
        Set<String> setVS;

        /**
         * void loop2(int *arr, int len) { int i;
         * for (i = 0; i < len; i++) { arr[i] = i; } }
         */
        /**
          0x400597={VRSP -8=[VRBP], RSP=[VRSP -8]}
 0x400598={RBP=[VRSP -8]}
 0x40059b={VRSP -32=[VRDI]}
 0x40059f={VRSP -36=[VRSI]}
 0x4005a2={VRSP -12=[0]}
 0x4005ab={RAX=[0, 1, 2, 3, VINF], VRSP -12=[0, 1, 2, 3, VINF]}
 0x4005b0={RDX=[VINF, 4, 5, 6, 7]}
 0x4005b8={RAX=[VRDI], VRSP -32=[VRDI]}
 0x4005bc={RDX=[VRDI +8, VRDI +5, VRDI +4, VRDI +7, VRDI +6]}
 0x4005bf={RAX=[0, 1, 2, 3, VINF], VRSP -12=[0, 1, 2, 3, VINF]}
 0x4005c2={VRDI +8=[4], VRDI +5=[1], VRDI +4=[0], VRDI +7=[3], VRDI +6=[2]}
 0x4005c4={VRSP -12=[1, 2, 3, VINF, 4]}
 0x4005c8={RAX=[0, 1, 2, 3, VINF], VRSP -12=[0, 1, 2, 3, VINF]}
 0x4005cb={VRSP -36=[VRSI]}
 0x4005d1={RBP=[VRBP], RSP=[VRSP]}
         */

        mapSMAT = new HashMap<>();
        /* 0x400597={VRSP -8=[VRBP], RSP=[VRSP -8]}*/
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRBP"));
        mapVS.put("VRSP -8", setVS);
        setVS = new HashSet<>(Arrays.asList("VRSP -8"));
        mapVS.put("RSP", setVS);
        mapSMAT.put(0x400597L, mapVS);

        /* 0x400598={RBP=[VRSP -8]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRSP -8"));
        mapVS.put("RBP", setVS);
        mapSMAT.put(0x400598L, mapVS);

        /* 0x40059b={VRSP -32=[VRDI]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRDI"));
        mapVS.put("VRSP -32", setVS);
        mapSMAT.put(0x40059bL, mapVS);

        /* 0x40059f={VRSP -36=[VRSI]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRSI"));
        mapVS.put("VRSP -36", setVS);
        mapSMAT.put(0x40059fL, mapVS);

        /* 0x4005a2={VRSP -12=[0]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("0"));
        mapVS.put("VRSP -12", setVS);
        mapSMAT.put(0x4005a2L, mapVS);

/* 0x4005ab = {RAX=[0, 1, 2, 3, VINF], VRSP -12=[0, 1, 2, 3, VINF]} */
mapVS = new HashMap<>();
setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
mapVS.put("RAX", setVS);
setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
mapVS.put("VRSP -12", setVS);
mapSMAT.put(0x4005abL, mapVS);

/* 0x4005b0={RDX=[VINF, 4, 5, 6, 7]} */
mapVS = new HashMap<>();
setVS = new HashSet<>(Arrays.asList("VINF", "4", "5", "6", "7"));
mapVS.put("RDX", setVS);
mapSMAT.put(0x4005b0L, mapVS);

/* 0x4005b8={RAX=[VRDI], VRSP -32=[VRDI]} */
mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRDI"));
        mapVS.put("RAX", setVS);
        setVS = new HashSet<>(Arrays.asList("VRDI"));
        mapVS.put("VRSP -32", setVS);
        mapSMAT.put(0x4005b8L, mapVS);

        /* 0x4005bc={RDX=[VRDI +8, VRDI +5, VRDI +4, VRDI +7, VRDI +6]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRDI +8", "VRDI +5", "VRDI +4", "VRDI +7", "VRDI +6"));
        mapVS.put("RDX", setVS);
        mapSMAT.put(0x4005bcL, mapVS);

        /* 0x4005bf={RAX=[0, 1, 2, 3, VINF], VRSP -12=[0, 1, 2, 3, VINF]} */
mapVS = new HashMap<>();
setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
mapVS.put("RAX", setVS);
setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
mapVS.put("VRSP -12", setVS);
mapSMAT.put(0x4005bfL, mapVS);

/* 0x4005c2={VRDI +8=[4], VRDI +5=[1], VRDI +4=[0], VRDI +7=[3], VRDI +6=[2]} */
        setVS = new HashSet<>(Arrays.asList("4"));
        mapVS.put("VRDI +8", setVS);
        setVS = new HashSet<>(Arrays.asList("1"));
        mapVS.put("VRDI +5", setVS);
        setVS = new HashSet<>(Arrays.asList("0"));
        mapVS.put("VRDI +4", setVS);
        setVS = new HashSet<>(Arrays.asList("3"));
        mapVS.put("VRDI +7", setVS);
        setVS = new HashSet<>(Arrays.asList("2"));
        mapVS.put("VRDI +6", setVS);
        mapSMAT.put(0x4005c2L, mapVS);

/* 0x4005c4={VRSP -12=[1, 2, 3, VINF, 4]} */
mapVS = new HashMap<>();
setVS = new HashSet<>(Arrays.asList("1", "2", "3", "VINF", "4"));
mapVS.put("VRSP -12", setVS);
mapSMAT.put(0x4005c4L, mapVS);

 /* 0x4005c8={RAX=[0, 1, 2, 3, VINF], VRSP -12=[0, 1, 2, 3, VINF]} */
 mapVS = new HashMap<>();
 setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
 mapVS.put("RAX", setVS);
 setVS = new HashSet<>(Arrays.asList("0", "1", "2", "3", "VINF"));
 mapVS.put("VRSP -12", setVS);
 mapSMAT.put(0x4005c8L, mapVS);

/* 0x4005cb={VRSP -36=[VRSI]} */
        mapVS = new HashMap<>();
        setVS = new HashSet<>(Arrays.asList("VRSI"));
        mapVS.put("VRSP -36", setVS);
        mapSMAT.put(0x4005cbL, mapVS);

/* 0x4005d1={RBP=[VRBP], RSP=[VRSP]}*/
mapVS = new HashMap<>();
setVS = new HashSet<>(Arrays.asList("VRBP"));
mapVS.put("VRSP -8", setVS);
setVS = new HashSet<>(Arrays.asList("VRSP -8"));
mapVS.put("RSP", setVS);
mapSMAT.put(0x4005d1L, mapVS);

        ArrayInfer infer = new ArrayInfer();
        Set<Map<String, List<Long>>> arrayAccess = infer.findArrayAccess(mapSMAT);

        System.out.println(arrayAccess.toString());

        Map<String, List<Long>> scopeAccess = infer.findScopeAccesssWOArray(mapSMAT);

        System.out.println(scopeAccess.toString());

        Set<String> info = infer.inferArray(arrayAccess, scopeAccess);
        for (String msg : info) {
            System.out.println(msg);
        }
    }
}

public class TestArrayInfer {

    public static void main(String[] args) {
        TestClass test = new TestClass();
        test.doTest();
    }
}
import java.util.*;

import symbolicVSA.*;

class TestClass {

    private SMARTable table;

    TestClass() {
        table = new SMARTable();
    }

    public void doTest() {
        Set<String> setVS;
        Map<String, Set<String>> mapVS;
        gegMap<Long, Map<String, Set<String>>> mapSMAT = new HashMap<>();

        /**
         * int main (int argc, char *argv[]) { int arr[20]; int i;
         * for (i = 0; i < 20; i++) { arr[i] = i; } return 0; }
         */
        
        /**
         * {4195682={RAX=[0]} 4195715={RAX=[0x0]} 4195684={VRSP -108=[0]} 4195654={VRSP
         * -8=[VRBP], RSP=[VRSP -8]} 4195655={RBP=[VRSP -8]} 4195720={RCX=[V(VFS+40)],
         * VRSP -16=[V(VFS+40)]} 4195658={RSP=[VRSP -136]} 4195724={VFS +40=[V(VFS+40)],
         * RCX=[0]} 4195693={RAX=[0, 1, 2, 3, VINF], VRSP -108=[0, 1, 2, 3, VINF]}
         * 4195662={VRSP -124=[VRDI]} 4195665={VRSP -136=[VRSI]} 4195698={RDX=[0, 1, 2,
         * 3, VINF], VRSP -108=[0, 1, 2, 3, VINF]} 4195701={VRSP -104=[0], VRSP -92=[3],
         * VRSP -100=[1], VRSP -96=[2]} 4195669={VFS +40=[V(VFS+40)], RAX=[V(VFS+40)]}
         * 4195705={VRSP -108=[1, 2, 3, VINF, 4]} 4195740={RBP=[VRBP], RSP=[VRSP, VRSP
         * -8]} 4195709={VRSP -108=[0, 1, 2, 3, VINF]} 4195741={RSP=[VRSP +8]}
         * 4195678={VRSP -16=[V(VFS+40)]}}
         */

        setVS = new HashSet<>(Arrays.asList("1", "2", "3", "4"));
        mapVS = new HashMap<>();
        mapSMAT = new HashMap<>();

        mapVS.put("0x40000", setVS);

        System.out.println("Run doTest successfully");
    }
}

public class TestSMARTable {

    public static void main(String[] args) {
        TestClass test = new TestClass();
        test.doTest();
    }
}
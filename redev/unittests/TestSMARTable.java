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
        Map<Long, Map<String, Set<String>>> mapSMAT;
        
        setVS = new HashSet<>(Arrays.asList("1", "2", "3", "4"));
        mapVS = new HashMap<>();
        mapSMAT = new HashMap<> ();

        mapVS.put("0x40000", setVS);

        
        mapSMAT.put(0x80000L, mapVS);
        assert(mapSMAT.size() == 1);

        /* test putAll method */
        table.putAll(mapSMAT);
        assert(table.size() == mapSMAT.size());
        assert(table.containsAll(mapSMAT));

        /* Assume it is not a shallow copy */
        mapSMAT.clear();
        assert(table.size() == 1);

        /* Test get method */
        mapVS = table.get(0x90000L);
        assert(mapVS == null);

        mapVS = table.get(0x80000L);
        assert(mapVS != null);

        /* Add more data */
        Set<String> setVSTemp;
        Map<String, Set<String>> mapVSTemp;
        Map<Long, Map<String, Set<String>>> mapSMATTemp;

        /* The same line of code access another memory address 0x40010*/
        setVSTemp = new HashSet<>(Arrays.asList("0", "5", "1", "2"));
        mapVSTemp = new HashMap<>();

        mapVSTemp.put("0x40010", setVSTemp);
        table.put(0x80000L, mapVSTemp);
        assert(table.size() == 1);

        mapVS = table.get(0x80000L);
        // System.out.println(String.format("62: size of map is (%d)", mapVS.size()));
        assert(mapVS.size() == 2);    
        setVS = mapVS.get("0x40000");
        assert(setVS != null);
        setVS = mapVS.get("0x40010");
        assert(setVS != null);

        /* The same line of code access another memory address 0x40020*/
        setVSTemp = new HashSet<>(Arrays.asList("0", "5", "VRSP", "VRAX"));
        mapVSTemp = new HashMap<>();
        mapVSTemp.put("0x40020", setVSTemp);
        table.put(0x80000L, mapVSTemp);
        assert(table.size() == 1);
        mapVS = table.get(0x80000L);
        assert(mapVS.size() == 3); 

        /* The same line of code access another memory address 0x40040*/
        setVSTemp = new HashSet<>(Arrays.asList("0", "5", "VINF", "VRSP"));
        mapVSTemp = new HashMap<>();
        mapVSTemp.put("0x40040", setVSTemp);
        table.put(0x80000L, mapVSTemp);
        assert(table.size() == 1);
        mapVS = table.get(0x80000L);
        assert(mapVS.size() == 4); 

        /* Containing test at address 0x40000: ("1", "2", "3", "4") */
        setVSTemp = new HashSet<>(Arrays.asList("1", "3"));
        mapVSTemp = new HashMap<>();
        mapVSTemp.put("0x40000", setVSTemp);
        mapSMATTemp = new HashMap<>();
        mapSMATTemp.put(0x80000L, mapVSTemp);
        assert(table.containsAll(mapSMATTemp));

        setVSTemp = new HashSet<>(Arrays.asList("5"));
        mapVSTemp = new HashMap<>();
        mapVSTemp.put("0x40000", setVSTemp);
        mapSMATTemp = new HashMap<>();
        mapSMATTemp.put(0x80000L, mapVSTemp);
        assert(!table.containsAll(mapSMATTemp));

        /* widening at address 0x40000 */
        table.putAll(mapSMATTemp);
        /* Containing test after widening */
        assert(table.containsAll(mapSMATTemp));

        /* Containing test at address 0x40040: ("0", "5", "VINF", "VRSP") */
        setVSTemp = new HashSet<>(Arrays.asList("1", "3"));
        mapVSTemp = new HashMap<>();
        mapVSTemp.put("0x40040", setVSTemp);
        mapSMATTemp = new HashMap<>();
        mapSMATTemp.put(0x80000L, mapVSTemp);
        assert(table.containsAll(mapSMATTemp)); // Because of VINF   
        
        System.out.println("Run doTest successfully");
    }
}


public class TestSMARTable {
    
    public static void main(String[] args) {
        TestClass test = new TestClass();
        test.doTest();        
    }
}
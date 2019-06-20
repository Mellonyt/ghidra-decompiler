
import symbolicVSA.*;

class TestClass {

    private SymbolicCalculator calc;

    TestClass() {
        calc = SymbolicCalculator.getCalculator();
    }

    public void doTest() {
        testLL();
        testSL();
        testSS();
    }

    private void testLL() {
        try {
            long res;

            res = calc.binaryOP(0, '+', 0);
            assert (res == 0);

            res = calc.binaryOP(10, '+', 0);
            assert (res == 10);

            res = calc.binaryOP(0, '+', 10);
            assert (res == 10);

            res = calc.binaryOP(10, '+', 20);
            assert (res == 30);

            res = calc.binaryOP(0, '-', 10);
            assert (res == -10);

            res = calc.binaryOP(10, '-', 0);
            assert (res == 10);

            res = calc.binaryOP(20, '-', 10);
            assert (res == 10);

            res = calc.binaryOP(10, '-', 20);
            assert (res == -10);

            res = calc.binaryOP(10, '*', 0);
            assert (res == 0);

            res = calc.binaryOP(-10, '*', 0);
            assert (res == 0);

            res = calc.binaryOP(0, '*', 10);
            assert (res == 0);

            res = calc.binaryOP(10, '*', 10);
            assert (res == 100);

            res = calc.binaryOP(10, '/', 10);
            assert (res == 1);

            res = calc.binaryOP(100, '/', 10);
            assert (res == 10);

            res = calc.binaryOP(10, '/', 100);
            assert (res == 0);

            res = calc.binaryOP(10, '^', 10);
            assert (res == 0);

            res = calc.binaryOP(100, '^', 10);
            assert (res != 0);

            System.out.println("Run TestLL successful");  

        } catch (Exception e) {
            String msg = String.format("72: Error in testLL -> %s", e.toString());
            System.err.println(msg);
        }
    }

    private void testSL() {
        try {
            String res;

            res = calc.symbolicBinaryOP("0", '+', 0);
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("VRSP", '+', 0);
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("VRSP -10", '+', 10);
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("VRSP +10", '+', 20);
            assert (res.equals("VRSP +30"));

            res = calc.symbolicBinaryOP("0", '-', 10);
            assert (res.equals("-10"));

            res = calc.symbolicBinaryOP("VRSP", '-', 0);
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("VRSP -10", '-', 10);
            assert (res.equals("VRSP -20"));

            res = calc.symbolicBinaryOP("VRSP +10", '-', 10);
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("0", '*', 0);
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("-10", '*', 0);
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("VRSP", '*', 10);
            assert (res.equals("D(VRSP*10)"));

            res = calc.symbolicBinaryOP("VRSP +10", '*', 10);
            assert (res.equals("D(VRSP*10) +100"));

            res = calc.symbolicBinaryOP("VRSP +10", '*', -10);
            assert (res.equals("D(VRSP*-10) -100"));

            res = calc.symbolicBinaryOP("0", '/', 10);
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("10", '/', 10);
            assert (res.equals("1"));

            res = calc.symbolicBinaryOP("VRSP", '/', 10);
            assert (res.equals("D(VRSP/10)"));

            res = calc.symbolicBinaryOP("VRSP -10", '/', 100);
            assert (res.equals("D(VRSP-10/100)"));

            res = calc.symbolicBinaryOP("VRSP +10", '/', 100);
            assert (res.equals("D(VRSP+10/100)"));

            res = calc.symbolicBinaryOP("VRSP +100", '/', 10);
            assert (res.equals("D(VRSP/10) +10"));

            res = calc.symbolicBinaryOP("100", '^', 100);
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("VRSP", '^', 100);
            assert (res.equals("D(VRSP^100)"));

            res = calc.symbolicBinaryOP("VRSP +10", '^', 100);
            assert (res.equals("D(VRSP+10^100)"));

            System.out.println("Run TestSL successful");  

        } catch (Exception e) {
            String msg = String.format("72: Error in testLL -> %s", e.toString());
            System.err.println(msg);
        }
    }

    private void testSS() {
        try {
            String res;

            res = calc.symbolicBinaryOP("0", '+', "0");
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("VRSP", '+', "0");
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("VRSP -10", '+', "10");
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("VRSP +10", '+', "20");
            assert (res.equals("VRSP +30"));

            res = calc.symbolicBinaryOP("VRSP", '+', "VRAX");
            assert (res.equals("D(VRSP+VRAX)"));

            res = calc.symbolicBinaryOP("VRSP +10", '+', "VRAX");
            assert (res.equals("D(VRSP+VRAX) +10"));

            res = calc.symbolicBinaryOP("VRSP +10", '+', "VRAX +10");
            assert (res.equals("D(VRSP+VRAX) +20"));

            res = calc.symbolicBinaryOP("0", '-', "10");
            assert (res.equals("-10"));

            res = calc.symbolicBinaryOP("VRSP", '-', "0");
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("VRSP -10", '-', "10");
            assert (res.equals("VRSP -20"));

            res = calc.symbolicBinaryOP("VRSP +10", '-', "10");
            assert (res.equals("VRSP"));

            res = calc.symbolicBinaryOP("VRSP", '-', "VRAX");
            assert (res.equals("D(VRSP-VRAX)"));

            res = calc.symbolicBinaryOP("VRSP +10", '-', "VRAX");
            assert (res.equals("D(VRSP-VRAX) +10"));

            res = calc.symbolicBinaryOP("VRSP +10", '-', "VRAX +10");
            assert (res.equals("D(VRSP-VRAX)"));

            res = calc.symbolicBinaryOP("0", '*', "0");
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("-10", '*', "0");
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("VRSP", '*', "10");
            assert (res.equals("D(VRSP*10)"));

            res = calc.symbolicBinaryOP("VRSP +10", '*', "10");
            assert (res.equals("D(VRSP*10) +100"));

            res = calc.symbolicBinaryOP("VRSP +10", '*', "-10");
            assert (res.equals("D(VRSP*-10) -100"));

            res = calc.symbolicBinaryOP("VRSP", '*', "VRAX");
            assert (res.equals("D(VRSP*VRAX)"));

            res = calc.symbolicBinaryOP("VRSP +10", '*', "VRAX");
            assert (res.equals("D(D(VRSP*VRAX)+D(VRAX*10))"));

            res = calc.symbolicBinaryOP("VRSP +10", '*', "VRAX +10");
            assert (res.equals("D(D(D(VRSP*VRAX)+D(VRSP*10))+D(VRAX*10)) +100"));

            res = calc.symbolicBinaryOP("0", '/', "10");
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("10", '/', "10");
            assert (res.equals("1"));

            res = calc.symbolicBinaryOP("VRSP", '/', "10");
            assert (res.equals("D(VRSP/10)"));

            res = calc.symbolicBinaryOP("VRSP -10", '/', "100");
            assert (res.equals("D(VRSP-10/100)"));

            res = calc.symbolicBinaryOP("VRSP +10", '/', "100");
            assert (res.equals("D(VRSP+10/100)"));

            res = calc.symbolicBinaryOP("VRSP +100", '/', "10");
            assert (res.equals("D(VRSP/10) +10"));

            res = calc.symbolicBinaryOP("VRSP", '/', "VRAX");
            assert (res.equals("D(VRSP/VRAX)"));

            res = calc.symbolicBinaryOP("VRSP +100", '/', "VRAX");
            assert (res.equals("D(VRSP+100/VRAX)"));

            res = calc.symbolicBinaryOP("VRSP +100", '/', "VRAX -10");
            // System.out.println(String.format("190: (%s)", res));
            assert (res.equals("D(VRSP+100/VRAX-10)"));

            res = calc.symbolicBinaryOP("100", '^', "100");
            assert (res.equals("0"));

            res = calc.symbolicBinaryOP("VRSP", '^', "100");
            assert (res.equals("D(VRSP^100)"));

            res = calc.symbolicBinaryOP("VRSP +10", '^', "100");
            // System.out.println(String.format("228: (%s)", res));
            assert (res.equals("D(VRSP+10^100)"));

            res = calc.symbolicBinaryOP("VRSP", '^', "VRAX");
            // System.out.println(String.format("264: (%s)", res));
            assert (res.equals("D(VRSP^VRAX)"));

            res = calc.symbolicBinaryOP("VRSP +10", '^', "VRAX");
            // System.out.println(String.format("268: (%s)", res));
            assert (res.equals("D(VRSP+10^VRAX)"));
            
            res = calc.symbolicBinaryOP("VRSP +10", '^', "VRAX +5");
            // System.out.println(String.format("270: (%s)", res));
            assert (res.equals("D(VRSP+10^VRAX+5)"));

            System.out.println("Run TestSS successful");  

        } catch (Exception e) {
            String msg = String.format("72: Error in testLL -> %s", e.toString());
            System.err.println(msg);
        }
    }
}

public class TestSymbolicCalculator {
    public static void main(String str[]) {

        TestClass test = new TestClass();
        test.doTest();
    }
}
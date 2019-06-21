package symbolicVSA;

import java.lang.Math;
import java.text.DecimalFormat;

import symbolicVSA.VSAException;

class InvalidSymboicValue extends VSAException {
    private static final long serialVersionUID = 1L;
    private String m_lineno, m_symbol;

    public InvalidSymboicValue(String lineno, String symbol) {
        m_lineno = lineno;
        m_symbol = symbol;
    }

    public String toString() {
        return String.format("%s: InvalidSymboicValue -> %s", m_lineno, m_symbol);
    }
}

class InvalidSymboicOP extends VSAException {
    private static final long serialVersionUID = 1L;
    private String m_lineno, m_msg;

    public InvalidSymboicOP(String lineno, String message) {
        m_lineno = lineno;
        m_msg = message;
    }

    public String toString() {
        return String.format("%s: InvalidSymboicOP -> %s", m_lineno, m_msg);
    }
}

/**
 * Encapsulate calculatoin for symbolic values
 * Singleton mode
 */
public class SymbolicCalculator {
    
    private static SymbolicCalculator m_calc = null;    // Singleton mode
    
    final DecimalFormat m_digitFmt; // Add a +/- sign before digit values

    private SymbolicCalculator() {
        m_digitFmt = new DecimalFormat("+#;-#");
    }

    public static SymbolicCalculator getCalculator() {
        if (m_calc == null) {
            m_calc = new SymbolicCalculator();
        }
        return m_calc;
    }

    public String symbolicAdd(String symbol0, String symbol1) {
        assert (isSymbolicValue(symbol0) && isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '+', symbol1);
    }

    public String symbolicSub(String symbol0, String symbol1) {
        assert (isSymbolicValue(symbol0) && isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '-', symbol1);
    }

    public String symbolicMul(String symbol0, String symbol1) {
        assert (isSymbolicValue(symbol0) && isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '*', symbol1);
    }

    public String symbolicDiv(String symbol0, String symbol1) {
        assert (isSymbolicValue(symbol0) && isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '/', symbol1);
    }

    public String symbolicXor(String symbol0, String symbol1) {
        assert (isSymbolicValue(symbol0) && isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '^', symbol1);
    }

    /**
     * Binary operations for two symbolic values.
     *
     * @param symbol0
     * @param op
     * @param symbol1
     * @return
     */
    public String symbolicBinaryOP(String symbol0, char op, String symbol1) {
        String[] elems0 = symbol0.split("\\s", 0);
        String[] elems1 = symbol1.split("\\s", 0);

        /* parse the symbolic value symbol0 */
        String part0S; // Symbolic part in symbol0
        long part0V; // Value part in symbol0

        if (elems0.length == 1) {
            if (isPureDigital(elems0[0])) {
                part0S = "0";
                part0V = Long.decode(elems0[0]);
            } else if (isPureSymbolic(elems0[0])) {
                part0S = elems0[0];
                part0V = 0;
            } else {
                throw new InvalidSymboicValue("1833", symbol0);
            }
        } else if (elems0.length == 2) {
            part0S = elems0[0];
            part0V = Long.decode(elems0[1]);
        } else {
            /* We assume each value has at most two parts. */
            throw new InvalidSymboicValue("1841", symbol0);
        }

        /* parse the symbolic value symbol1 */
        String part1S; // Symbolic part in symbol0
        long part1V; // Value part in symbol0

        if (elems1.length == 1) {
            if (isPureDigital(elems1[0])) {
                part1S = "0";
                part1V = Long.decode(elems1[0]);
            } else if (isPureSymbolic(elems1[0])) {
                part1S = elems1[0];
                part1V = 0;
            } else {
                throw new InvalidSymboicValue("1859", symbol1);
            }
        } else if (elems1.length == 2) {
            part1S = elems1[0];
            part1V = Long.decode(elems1[1]);
        } else {
            /* We assume each value has at most two parts. */
            throw new InvalidSymboicValue("1867", symbol1);
        }

        /* calculate the result */
        String tmpS, newSymbol;
        long tmpV;

        if (op == '+' || op == '-') {
            tmpS = binaryOP(part0S, op, part1S);
            tmpV = binaryOP(part0V, op, part1V);
            newSymbol = binaryOP(tmpS, '+', tmpV);

        } else if (op == '*') {
            if (part0S.equals("0") || part1S.equals("0")) {
                if (part0S.equals("0")) {
                    tmpS = binaryOP(part1S, '*', part0V);
                } else {
                    tmpS = binaryOP(part0S, '*', part1V);
                }

                tmpV = binaryOP(part0V, '*', part1V);
                newSymbol = binaryOP(tmpS, '+', tmpV);

            } else {
                String tmpL, tmpR;

                tmpS = binaryOP(part0S, '*', part1S);
                tmpL = binaryOP(part0S, '*', part1V);
                tmpR = binaryOP(part1S, '*', part0V);
                tmpV = binaryOP(part0V, '*', part1V);

                newSymbol = binaryOP(tmpS, '+', tmpL);
                newSymbol = binaryOP(newSymbol, '+', tmpR);
                newSymbol = binaryOP(newSymbol, '+', tmpV);
            }

        } else if (op == '/') {
            if (symbol0.equals(symbol1)) {
                newSymbol = "1";

            } else if (part0S.equals("0") && part0V == 0) {
                newSymbol = "0";

            } else if (part0S.equals("0") && part1S.equals("0")) {
                tmpV = binaryOP(part0V, '/', part1V);
                newSymbol = binaryOP("0", '+', tmpV);

            } else if (!part0S.equals("0") && part1S.equals("0")) {
                /* (VRSP + 100)/10 or VRSP/10 */
                if (part0V == 0) {
                    newSymbol = String.format("D(%s/%d)", part0S, part1V);
                } else {
                    if (part0V % part1V == 0) {
                        newSymbol = String.format("D(%s/%d) %s", part0S, part1V, m_digitFmt.format(part0V / part1V));
                    } else {
                        newSymbol = String.format("D(%s%s/%d)", part0S, m_digitFmt.format(part0V), part1V);
                    }
                }
            } else if (part0S.equals("0") && !part1S.equals("0")) {
                if (part1V == 0) {
                    newSymbol = String.format("D(%d/%s)", part0V, part1S);
                } else {
                    newSymbol = String.format("D(%d/%s%s)", part0V, part1S, m_digitFmt.format(part1V));
                }

            } else {
                part0S = symbol0.replaceAll("\\s", "");
                part1S = symbol1.replaceAll("\\s", "");
                newSymbol = String.format("D(%s/%s)", part0S, part1S);
            }

        } else if (op == '^') {
            if (symbol0.equals(symbol1)) {
                newSymbol = "0";
            } else {
                part0S = symbol0.replaceAll("\\s", "");
                part1S = symbol1.replaceAll("\\s", "");
                newSymbol = String.format("D(%s^%s)", part0S, part1S);
            }
        } else {
            /* Thow exception */
            String msg = String.format("(%s) %s (%s)", symbol0, Character.toString(op), symbol1);
            throw new InvalidSymboicOP("2140", msg);
        }

        return newSymbol;
    }

    public String symbolicAdd(String symbol, long value) {
        assert (isSymbolicValue(symbol));
        return symbolicBinaryOP(symbol, '+', value);
    }

    public String symbolicSub(String symbol, long value) {
        assert (isSymbolicValue(symbol));
        return symbolicBinaryOP(symbol, '-', value);
    }

    public String symbolicMul(String symbol, long value) {
        assert (isSymbolicValue(symbol));
        return symbolicBinaryOP(symbol, '*', value);
    }

    public String symbolicDiv(String symbol, long value) {
        assert (isSymbolicValue(symbol));
        return symbolicBinaryOP(symbol, '/', value);
    }

    /**
     * Binary operation for a symbolic-value and an integer value
     *
     * @param symbol
     * @param op
     * @param value
     * @return A symbolic-value
     */
    public String symbolicBinaryOP(String symbol, char op, long value) {
        String[] elems = symbol.split("\\s", 0);

        /* parse the symbolic value */
        String partS; // symbolic part of symbol
        long partV; // Numeric part of symbol

        if (elems.length == 1) {
            if (isPureDigital(elems[0])) {
                partS = "";
                partV = Long.decode(elems[0]);
            } else if (isPureSymbolic(elems[0])) {
                partS = elems[0];
                partV = 0;
            } else {
                throw new InvalidSymboicValue("1933", symbol);
            }

        } else if (elems.length == 2) {
            partS = elems[0];
            partV = Long.decode(elems[1]);

        } else {
            /* We assume the symbolic value has at most two parts */
            String msg = String.format("%s has more than two parts", symbol);
            throw new InvalidSymboicOP("1970", msg);
        }

        String newSymbol;
        long newValue;

        if (partS.equals("")) {
            newValue = binaryOP(partV, op, value);
            newSymbol = binaryOP("0", '+', newValue);

        } else if (partV == 0) {
            newSymbol = binaryOP(partS, op, value);

        } else {
            if (op == '+' || op == '-') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, '+', newValue);

            } else if (op == '*') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, op, value);
                newSymbol = binaryOP(newSymbol, '+', newValue);

            } else if (op == '/') {
                if (partV % value == 0) {
                    newValue = binaryOP(partV, op, value);
                    newSymbol = binaryOP(partS, op, value);
                    newSymbol = binaryOP(newSymbol, '+', newValue);
                } else {
                    newSymbol = String.format("D(%s%s/%d)", partS, m_digitFmt.format(partV), value);
                }

            } else if (op == '^') {
                newSymbol = String.format("D(%s%s^%d)", partS, m_digitFmt.format(partV), value);

            } else {
                String msg = String.format("(%s) %s %d", symbol, Character.toString(op), value);
                throw new InvalidSymboicOP("2024", msg);
            }
        }

        return newSymbol;
    }

    /**
     * Binary operation for two pure-symbolic values
     *
     * @param pure_symbol0
     * @param op
     * @param pure_symbol1
     * @return
     */
    private String binaryOP(String pure_symbol0, char op, String pure_symbol1) {
        assert (isPureSymbolic(pure_symbol0));
        assert (isPureSymbolic(pure_symbol1));

        String newSymbol;
        long newValue;

        if (isZero(pure_symbol0))
            pure_symbol0 = "";
        if (isZero(pure_symbol1))
            pure_symbol1 = "";

        if (op == '+') {
            if (pure_symbol0.equals("") || pure_symbol1.equals("")) {
                newSymbol = pure_symbol0 + pure_symbol1;
                if (newSymbol.equals(""))
                    newSymbol = "0";

            } else if (pure_symbol0.equals("-" + pure_symbol1) || pure_symbol1.equals("-" + pure_symbol0)) {
                newSymbol = "0";
            } else {
                /* Cannot parse */
                newSymbol = String.format("D(%s+%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '-') {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "0";
            } else if (pure_symbol0.equals("")) {
                newSymbol = String.format("-%s", pure_symbol1);
            } else if (pure_symbol1.equals("")) {
                newSymbol = pure_symbol0;
            } else {
                /* Cannot parse */
                newSymbol = String.format("D(%s-%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '*') {
            if (pure_symbol0.equals("") || pure_symbol1.equals("")) {
                newSymbol = "0";
            } else {
                newSymbol = String.format("D(%s*%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '/') {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "1";
            } else if (pure_symbol0.equals("")) {
                newSymbol = "0";
            } else if (pure_symbol1.equals("")) {
                String msg = String.format("(%s) %s (%s)", pure_symbol0, Character.toString(op), pure_symbol1);
                throw new InvalidSymboicOP("2140", msg);
            } else {
                newSymbol = String.format("D(%s/%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '^') {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "0";
            } else {
                newSymbol = String.format("D(%s^%s)", pure_symbol0, pure_symbol1);
            }

        } else {
            String msg = String.format("(%s) %s (%s)", pure_symbol0, Character.toString(op), pure_symbol0);
            throw new InvalidSymboicOP("2140", msg);
        }

        return newSymbol;
    }

    /**
     * Binary operation for a pure-symbolic value and an integer value e.g. VRSP +
     * 0x8; VRSP - 0x8; VRSP * 0x8; VRSP / 0x8;
     *
     * @param pure_symbol
     * @param op
     * @param value
     * @return a symbolic value
     */
    private String binaryOP(String pure_symbol, char op, long value) {
        assert (isPureSymbolic(pure_symbol));

        String newSymbol;
        long newValue;

        if (isZero(pure_symbol))
            pure_symbol = "";

        if (pure_symbol.equals("")) {
            if (op == '+') {
                newValue = value;
            } else if (op == '-') {
                newValue = 0 - value;
            } else if (op == '*') {
                newValue = 0;
            } else if (op == '/') {
                newValue = 0;
            } else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicOP("1560", msg);
            }
            newSymbol = String.format("%d", newValue);

        } else if (value == 0) {
            if (op == '+') {
                newSymbol = pure_symbol;
            } else if (op == '-') {
                newSymbol = pure_symbol;
            } else if (op == '*') {
                newSymbol = "0";
            } else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicOP("2140", msg);
            }

        } else {
            if (op == '+') {
                newValue = value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            } else if (op == '-') {
                newValue = 0 - value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            } else if (op == '*') {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                } else {
                    newSymbol = String.format("D(%s*%d)", pure_symbol, newValue);
                }
            } else if (op == '/') {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                } else {
                    newSymbol = String.format("D(%s/%s)", pure_symbol, newValue);
                }
            } else if (op == '^') {
                newValue = value;
                newSymbol = String.format("D(%s^%s)", pure_symbol, newValue);
            } else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicValue("2178", msg);
            }
        }

        return newSymbol;
    }

    /**
     * Binary operation for two long values: 0x12 + 0x34; 0x12 - 0x34; 0x12 * 0x34;
     * 0x12 / 0x34; 0x12 ^ 0x34
     *
     * @param value0
     * @param op
     * @param value1
     * @return
     */
    public long binaryOP(long value0, char op, long value1) {
        long res;

        if (op == '+') {
            res = value0 + value1;
        } else if (op == '-') {
            res = value0 - value1;
        } else if (op == '*') {
            res = value0 * value1;
        } else if (op == '/') {
            res = value0 / value1;
        } else if (op == '^') {
            res = value0 ^ value1;
        } else {
            throw new InvalidSymboicOP("2207", Character.toString(op));
        }
        return res;
    }

    public long symbolicBinaryOP(long value0, char op, long value1) {
        return binaryOP(value0, op, value1);
    }

    /**
     * Test if it is symbolic value: which is defined as: 1. starting with
     * (-)[V|D]xxx or 2. a digital value, 3. may contain spaces
     *
     * @param symbol
     * @return
     */
    public boolean isSymbolicValue(String symbol) {
        String[] parts = symbol.split("\\s", 0);

        for (String e : parts) {
            if (!(isPureSymbolic(e) || isPureDigital(e))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Test if it is a pure symbolic value, which is defined as: 1. [V|D]xxx 2.
     * ditigal 0; 3. no space, 4. sign-extended
     *
     * @param symbol
     * @return
     */
    public boolean isPureSymbolic(String symbol) {
        boolean yes;
        int len = symbol.length();

        if (symbol.length() < 1 || symbol.contains(" ")) {
            /* should no spaces */
            yes = false;
        } else if (isZero(symbol)) {
            yes = true;
        } else if ((symbol.charAt(0) == 'V') || (symbol.charAt(0) == 'D')) {
            yes = (symbol.length() > 1);
        } else if (symbol.charAt(0) == '-' && ((symbol.charAt(0) == 'V') || (symbol.charAt(0) == 'D'))) {
            /* sign extend */
            yes = (symbol.length() > 2);
        } else {
            yes = false;
        }

        return yes;
    }

    /**
     * Test if the symbol is zero or not
     *
     * @param symbol
     * @return
     */
    public boolean isZero(String symbol) {
        if (isPureDigital(symbol)) {
            long n = Long.decode(symbol);
            return (n == 0);
        }
        return false;
    }

    /**
     * Test if a symbolic value is pure digitvalue
     *
     * @param symbol
     * @return
     */
    public boolean isPureDigital(String symbol) {
        boolean yes = false;
        try {
            Long.decode(symbol);
            yes = true;
        } catch (Exception e) {

        }
        return yes;
    }

}

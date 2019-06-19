package ghidra.redev.symbolicVSA;

import java.lang.Math;
import java.text.DecimalFormat;

import ghidra.redev.symbolicVSA.SVSAException;


private class InvalidSymboicValue extends SVSAException {
    private String m_lineno, m_symbol;

    public InvalidSymboicValue(String lineno, String symbol) {
        m_lineno = lineno;
        m_symbol = symbol;
    }

    public String toString() {
        return String.format("%s: InvalidSymboicValue -> %s", m_lineno, m_symbol);
    }    
}


private class InvalidSymboicOP extends SVSAException {
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
 */
public class SymbolicCalculator {
    final DecimalFormat m_digitFmt;               // Add a +/- sign before digit values

    SymbolicCalculator() {
        m_digitFmt = new DecimalFormat("+#;-#");
    }

    public String symbolicAdd(String symbol0, String symbol1) {
        assert(_isSymbolicValue(symbol0) && _isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '+', symbol1);
    }


    public String symbolicSub(String symbol0, String symbol1) {
        assert(_isSymbolicValue(symbol0) && _isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '-', symbol1);
    }


    public String symbolicMul(String symbol0, String symbol1) {
        assert(_isSymbolicValue(symbol0) && _isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '*', symbol1);
    }


    public String symbolicDiv(String symbol0, String symbol1) {
        assert(_isSymbolicValue(symbol0) && _isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '/', symbol1);
    }

    public String symbolicXor(String symbol0, String symbol1) {
        assert(_isSymbolicValue(symbol0) && _isSymbolicValue(symbol1));
        return symbolicBinaryOP(symbol0, '^', symbol1);
    }


    /**
     * Binary operations for two symbolic values.
     * @param symbol0
     * @param op
     * @param symbol1
     * @return
     */
    public String symbolicBinaryOP(String symbol0, char op, String symbol1) {
        String[] elems0 = symbol0.split("\\s", 0);
        String[] elems1 = symbol1.split("\\s", 0);

        /* We assume each value has at most two parts. */
        if (elems0.length > 2) {
            throw InvalidSymboicValue("1810", symbol0);
        }

        if (elems1.length > 2) {
            throw InvalidSymboicValue("1814", symbol1);
        }


        /* parse the symbolic value symbol0 */
        String part0S;      // Symbolic part in symbol0
        long part0V;        // Value part in symbol0

        if (elems0.length == 1) {
            if (_isPureDigital(elems0[0])) {
                part0S = "0";
                part0V = Long.decode(elems0[0]);
            }
            else if (_isPureSymbolic(elems0[0])) {
                part0S = elems0[0];
                part0V = 0;
            }
            else {
                throw new InvalidSymboicValue("1833", symbol0);
            }
        }
        else if (elems0.length == 2) {
            part0S = elems0[0];
            part0V = Long.decode(elems0[1]);
        }
        else {
            throw InvalidSymboicValue("1841", symbol0);
        }

        /* parse the symbolic value symbol1 */
        String part1S;    // Symbolic part in symbol0
        long part1V;         // Value part in symbol0

        if (elems1.length == 1) {
            if (_isPureDigital(elems1[0])) {
                part1S = "0";
                part1V = Long.decode(elems1[0]);
            }
            else if (_isPureSymbolic(elems1[0])) {
                part1S = elems1[0];
                part1V = 0;
            }
            else {
                throw InvalidSymboicValue("1859", symbol1);
            }
        }
        else if (elems1.length == 2) {
            part1S = elems1[0];
            part1V = Long.decode(elems1[1]);
        }
        else {
            throw InvalidSymboicValue("1867", symbol1);
        }

        /* calculate the result */
        String tmpS, newSymbol;
        long tmpV;

        if (op == '+' || op == '-' ) {
            tmpS = binaryOP(part0S, op, part1S);
            tmpV = binaryOP(part0V, op,  part1V);
            newSymbol = binaryOP(tmpS, '+', tmpV);
        }
        else if (op == '*') {
            if (part0S == "" || part1S == "") {
                tmpS = part0S + part1S;
                if (part0S == "") {
                    tmpS = binaryOP(tmpS, '*', part0V);
                }
                else {
                    tmpS = binaryOP(tmpS, '*', part1V);
                }
                tmpV = binaryOP(part0V, '*', part1V);

                newSymbol = binaryOP(tmpS, '+', tmpV);
            }
            else {
                String tmpL, tmpR;
                tmpS = binaryOP(part0S, '*', part1S);
                tmpL = binaryOP(part0S, '*', part1V);
                tmpR = binaryOP(part1S, '*', part0V);
                tmpV = binaryOP(part0V, '*', part1V);

                newSymbol = binaryOP(tmpS, '+', tmpL);
                newSymbol = binaryOP(newSymbol, '+', tmpR);
                newSymbol = binaryOP(newSymbol, '+', tmpV);
            }
        }
        else if (op == '/') {
            if (symbol0 == symbol1) {
                newSymbol = "1";
            }
            else if (part0S == "" && part1S == "") {
                tmpV = binaryOP(part0V, '/', part1V);
                newSymbol = binaryOP("", '+', tmpV);
            }
            else {
                newSymbol = String.format("D(%s%s/%s%s)", part0S, m_digitFmt.format(part0V), part1S, m_digitFmt.format((part1V)));
            }
        }
        else {
            /* Thow exception */
            String msg = String.format("(%s) %s (%s)", symbol0, Character.toString(op), symbol1);
            throw new InvalidSymboicOP("2140", msg);
        }

        return newSymbol;
    }


    public String symbolicAdd(String symbol, long value) {
        assert(_isSymbolicValue(symbol));
        return symbolicBinaryOP(symbol, '+', value);
    }


    public String symbolicSub(String symbol, long value) {
        assert(_isSymbolicValue(symbol));
        return symbolicBinaryOP(symbol, '-', value);
    }


    public String symbolicMul(String symbol, long value) {
        assert(_isSymbolicValue(symbol));
        return symbolicBinaryOP(symbol, '*', value);
    }


    /* Binary operation */
    /**
     * Binary operation for a symbolic-value and an integer value
     * @param symbol
     * @param op
     * @param value
     * @return A symbolic-value
     */
    public String symbolicBinaryOP(String symbol, char op, long value) {
        String[] elems = symbol.split("\\s", 0);

        /* We assume the symbolic value has at most two parts */
        if (elems.length > 2) {
            String msg = String.format("%s has more than two parts", symbol);
            throw new InvalidSymboicOP("1970", msg);
        }

        /* parse the symbolic value */
        String partS;       // symbolic part of symbol
        long partV;         // Numeric part of symbol

        if (elems.length == 1) {
            if (_isPureDigital(elems[0])) {
                partS = "0";
                partV = Long.decode(elems[0]);
            }
            else if (_isPureSymbolic(elems[0])) {
                partS = elems[0];
                partV = 0;
            }
            else {
                throw new InvalidSymboicValue("1933", symbol);
            }
        }
        else if (elems.length == 2) {
            partS = elems[0];
            partV = Long.decode(elems[1]);
        }
        else {
            throw InvalidSymboicValue("1998", symbol);
        }

        String newSymbol;
        long newValue;

        if (partS == "") {
            newValue = binaryOP(partV, op, value);
            newSymbol = binaryOP("0", '+', newValue);
        }
        else if (partV == 0) {
            newSymbol = binaryOP(partS, op, value);
        }
        else {
            if (op == '+' || op == '-') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, '+', newValue);
            }
            else if (op == '*' || op == '/') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, op, value);
                newSymbol = binaryOP(newSymbol, '+', newValue);
            }
            else if (op == '^') {
                newSymbol = String.format("D(%s%s^%d)", partS, m_digitFmt.format(partV), value);
            }
            else {
                String msg = String.format("(%s) %s %d", symbol, Character.toString(op), value);
                throw new InvalidSymboicOP("2024", msg);
            }
        }

        return newSymbol;
    }


    /**
     * Binary operation for two pure-symbolic values
     * @param pure_symbol0
     * @param op
     * @param pure_symbol1
     * @return
     */
    private String binaryOP(String pure_symbol0, char op, String pure_symbol1) {
        assert(_isPureSymbolic(pure_symbol0));
        assert(_isPureSymbolic(pure_symbol1));

        String newSymbol;
        long newValue;

        if (pure_symbol0.equals("0")) pure_symbol0 = "";
        if (pure_symbol1.equals("0")) pure_symbol1 = "";

        if (op == '+') {
            if (pure_symbol0 == "" || pure_symbol1 == "" ) {
                newSymbol = pure_symbol0 + pure_symbol1;
            }
            else if (pure_symbol0.equals("-" + pure_symbol1) || pure_symbol1.equals("-" + pure_symbol0)) {
                newSymbol = "0";
            }
            else {
                /* Cannot parse */
                newSymbol = String.format("D(%s+%s)", pure_symbol0, pure_symbol1);
            }
        }
        else if (op == '-')  {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "0";
            }
            else if (pure_symbol0 == "") {
                newSymbol = String.format("-%s", pure_symbol1);
            }
            else if (pure_symbol1 == "" ) {
                newSymbol = pure_symbol0;
            }
            else {
                /* Cannot parse */
                newSymbol = String.format("D(%s-%s)", pure_symbol0, pure_symbol1);
            }
        }
        else if (op == '*')  {
            if (pure_symbol0 == "" || pure_symbol1 == "" ) {
                newSymbol = "0";
            }
            else {
                newSymbol = String.format("D(%s*%s)", pure_symbol0, pure_symbol1);
            }
        }
        else if (op == '/')  {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "1";
            }
            else if (pure_symbol0 == "") {
                newSymbol = "0";
            }
            else if (pure_symbol1 == "" ) {
                String msg = String.format("(%s) %s (%s)", pure_symbol0, Character.toString(op), pure_symbol1);
                throw new InvalidSymboicOP("2140", msg);
            }
            else {
                newSymbol = String.format("D(%s/%s)", pure_symbol0, pure_symbol1);
            }
        }
        else if (op == '^') {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "0";
            }
            else {
                newSymbol = String.format("D(%s^%s)", pure_symbol0, pure_symbol1);
            }
        }
        else {
            String msg = String.format("(%s) %s (%s)", pure_symbol0, Character.toString(op), pure_symbol0);
            throw new InvalidSymboicOP("2140", msg);
        }

        return newSymbol;
    }


    /**
     * Binary operation for a pure-symbolic value and an integer value
     * e.g. VRSP + 0x8; VRSP - 0x8; VRSP * 0x8; VRSP / 0x8;
     * @param pure_symbol
     * @param op
     * @param value
     * @return  a symbolic value
     */
    private String binaryOP(String pure_symbol, char op, long value) {
        assert(_isPureSymbolic(pure_symbol));

        String newSymbol;
        long newValue;

        if (pure_symbol == "0") pure_symbol = "";

        if (pure_symbol == "") {
            if (op == '+') {
                newValue = value;
            }
            else if (op == '-')  {
                newValue = 0 - value;
            }
            else if (op == '*')  {
                newValue = 0;
            }
            else if (op == '/')  {
                newValue = 0;
            }
            else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicOP("1560", msg);
            }

            newSymbol = String.format("%s", m_digitFmt.format(newValue));
        }
        else if (value == 0) {
            if (op == '+') {
                newSymbol = pure_symbol;
            }
            else if (op == '-')  {
                newSymbol = pure_symbol;
            }
            else if (op == '*')  {
                newSymbol = "0";
            }
            else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicOP("2140", msg);
            }
        }
        else {
            if (op == '+') {
                newValue = value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            }
            else if (op == '-')  {
                newValue = 0 - value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            }
            else if (op == '*')  {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                }
                else {
                    newSymbol = String.format("D(%s*%s)", pure_symbol, m_digitFmt.format(newValue));
                }
            }
            else if (op == '/')  {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                }
                else {
                    newSymbol = String.format("D(%s/%s)", pure_symbol, m_digitFmt.format(newValue));
                }
            }
            else if (op == '^')  {
                newValue = value;
                newSymbol = String.format("D(%s^%s)", pure_symbol, m_digitFmt.format(newValue));
            }
            else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicValue("2178", msg);
            }
        }

        return newSymbol;
    }


    /**
     * Binary operation for two long values: 0x12 + 0x34; 0x12 - 0x34; 0x12 * 0x34; 0x12 / 0x34; 0x12 ^ 0x34
     * @param value0
     * @param op
     * @param value1
     * @return
     */
    public long binaryOP(long value0, char op, long value1) {
        long res;

        if (op == '+') {
            res = value0 + value1;
        }
        else if (op == '-') {
            res = value0 - value1;
        }
        else if (op == '*') {
            res = value0 * value1;
        }
        else if (op == '/') {
            res = value0 / value1;
        }
        else if (op == '^') {
            res = value0 ^ value1;
        }
        else {
            throw new InvalidSymboicOP("2207", Character.toString(op));
        }
        return res;
    }


    /**
     * Test if it is symbolic value: which is defined as: 1. starting with (-)[V|D]xxx or 2. a digital value, 3. may contain spaces
     * @param symbol
     * @return
     */
    private boolean _isSymbolicValue(String symbol) {
        String[] parts = symbol.split("\\s", 0);

        for (String e : parts) {
            if (!(_isPureSymbolic(e) || _isPureDigital(e))) {
                return false;
            }
        }
        return true;
    }


    /**
     * Test if it is a pure symbolic value, which is defined as: 1. [V|D]xxx  2. ditigal 0; 3. no space, 4. sign-extended
     * @param symbol
     * @return
     */
    private boolean _isPureSymbolic(String symbol) {
        boolean yes;
        int len = symbol.length();

        if (symbol.length() < 1 || symbol.contains(" ")) {
            /* should no spaces */
            yes = false;
        }
        else if ((symbol.charAt(0) == 'V') || (symbol.charAt(0) == 'D')) {
            yes = (symbol.length() > 1);
        }
        else if (symbol.charAt(0) == '-' && ((symbol.charAt(0) == 'V') || (symbol.charAt(0) == 'D'))) {
            /* sign extend */
            yes = (symbol.length() > 2);
        }
        else {
            yes = false;
        }

        return yes;
    }


    /**
     * Test if a symbolic value is pure digitvalue
     * @param symbol
     * @return
     */
    private boolean _isPureDigital(String symbol) {
        boolean yes = false;
        try {
            Long.decode(symbol);
            yes = true;
        }
        catch (Exception e) {

        }
        return yes;
    }
}


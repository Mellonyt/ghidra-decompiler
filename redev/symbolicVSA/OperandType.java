package symbolicVSA;

class Register {
	private String m_name;

	public Register(String register_name) {
		m_name = register_name;
	}

	public String getName() {
		return m_name;
	}
}

class Scalar {
	private long m_value;

	public Scalar(long value) {
		m_value = value;
	}

	public long getValue() {
		return m_value;
	}
}

class GenericAddress {
	private long m_offset;

	public GenericAddress(long offset) {
		m_offset = offset;
	}

	public long getOffset() {
		return m_offset;
	}
}

public class OperandType {
	/**
	 * check the REGISTER flag.
	 * 
	 * @param operandType the bit field to examine.
	 *
	 * @return true if the REGISTER flag is set.
	 */
	public boolean isRegister(int operandType) {
		return true;
	}

	/**
	 * check SCALAR flag.
	 * 
	 * @param operandType the bit field to examine.
	 *
	 * @return true if the SCALAR flag is set
	 */
	public boolean isScalar(int operandType) {
		return true;
	}
}
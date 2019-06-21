package symbolicVSA.operand;

public class Scalar {
	private long m_value;

	public Scalar(long value) {
		m_value = value;
	}

	public long getValue() {
		return m_value;
	}

	public String toString() {
		return String.valueOf(m_value);
	}
}
package symbolicVSA.operand;

public class GenericAddress {
	private long m_offset;

	public GenericAddress(long offset) {
		m_offset = offset;
	}

	public long getOffset() {
		return m_offset;
	}

	public String toString() {
		return String.valueOf(m_offset);
	}
}
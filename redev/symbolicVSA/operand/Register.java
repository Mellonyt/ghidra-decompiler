package symbolicVSA.operand;

public class Register {
	private String m_name;

	public Register(String register_name) {
		m_name = register_name;
	}

	public String getName() {
		return m_name;
	}

	public String toString() {
		return m_name;
	}
}
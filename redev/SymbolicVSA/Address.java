package symbolicVSA;

public class Address {
    private long m_offset;

    public Address(long address) {
        m_offset = address;
    }

    public long getOffset() {
        return m_offset;
    }
}

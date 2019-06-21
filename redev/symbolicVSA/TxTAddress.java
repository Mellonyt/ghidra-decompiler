package symbolicVSA;

public class TxTAddress {
    private long m_offset;

    public TxTAddress(long address) {
        m_offset = address;
    }

    public long getOffset() {
        return m_offset;
    }
}
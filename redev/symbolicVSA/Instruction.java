package symbolicVSA;

import symbolicVSA.*;

public interface Instruction {
	/**
	 * Get the number of operands for this code unit.
	 */
	public int getNumOperands();

	/**
	 * Get the type of a specific operand.
	 *
	 * @param opIndex the index of the operand. (zero based)
	 * @return the type of the operand.
	 */
	public int getOperandType(int opIndex);

	/**
	 * Get the operand representation for the given operand index without markup.
	 *
	 * @param opIndex operand index
	 * 
	 * @return operand represented as a string.
	 */
	public String getDefaultOperandRepresentation(int opIndex);

	/**
	 * Get objects used by this operand (Address, Scalar, Register ...)
	 * 
	 * @param opIndex index of the operand.
	 */
	public Object[] getOpObjects(int opIndex);

	/**
	 * Get the mnemonic for this code unit, e.g., MOV, JMP
	 */
	public String getMnemonicString();

	/**
	 * Get the Address which corresponds to the offset 0.
	 *
	 * @return the current address of offset 0.
	 */
	public TxTAddress getAddress();

	/**
	 * Returns a string that represents this code unit with default markup. Only the
	 * mnemonic and operands are included.
	 * 
	 * @see CodeUnitFormat#getRepresentationString(CodeUnit, boolean) for full
	 *      mark-up formatting
	 */
	public String toString();
}
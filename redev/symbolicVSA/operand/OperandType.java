package symbolicVSA.operand;

import symbolicVSA.operand.*;

/**
 * 0: unknow 1: Register 2: Scalar 3: GenericAddress 4: Address
 */
public class OperandType {
	/**
	 * check the REGISTER flag.
	 * 
	 * @param operandType the bit field to examine.
	 *
	 * @return true if the REGISTER flag is set.
	 */
	public boolean isRegister(int operandType) {
		return (operandType == 1);
	}

	/**
	 * check SCALAR flag.
	 * 
	 * @param operandType the bit field to examine.
	 *
	 * @return true if the SCALAR flag is set
	 */
	public boolean isScalar(int operandType) {
		return (operandType == 2);
	}

	public boolean isAddress(int operandType) {
		return (operandType == 4);
	}
}
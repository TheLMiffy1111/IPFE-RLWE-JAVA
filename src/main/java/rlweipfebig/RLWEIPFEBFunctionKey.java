package rlweipfebig;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Holds the function y and the secret function key skY.
 */
public record RLWEIPFEBFunctionKey(BigInteger[] y, BigInteger[] skY) implements Serializable {

	public void validate(RLWEIPFEBParams params) {
		if(!CheckB.checkDims(y, params.l)) {
			throw new IllegalArgumentException("invalid y");
		}
		if(!CheckB.checkDims(skY, params.n)) {
			throw new IllegalArgumentException("invalid skY");
		}
	}
}

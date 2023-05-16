package rlweipfe;

import java.io.Serializable;

/**
 * Holds the function y and the secret function key skY.
 */
public record RLWEIPFEFunctionKey(int[][] y, int[][] skY) implements Serializable {

	public void validate(RLWEIPFEParams params) {
		if(!Check.checkDims(y, params.qN.length, params.l)) {
			throw new IllegalArgumentException("invalid y");
		}
		if(!Check.checkDims(skY, params.qN.length, params.n)) {
			throw new IllegalArgumentException("invalid skY");
		}
	}
}

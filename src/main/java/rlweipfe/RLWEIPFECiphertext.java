package rlweipfe;

import java.io.Serializable;

/**
 * Holds the ciphertext ct0 and ct, and the size of the encrypted message.
 */
public record RLWEIPFECiphertext(int n, int[][] ct0, int[][][] ct) implements Serializable {

	public void validate(RLWEIPFEParams params) {
		if(n > params.n) {
			throw new IllegalArgumentException("invalid n");
		}
		if(!Check.checkDims(ct0, params.qN.length, params.n)) {
			throw new IllegalArgumentException("invalid ct0");
		}
		if(!Check.checkDims(ct, params.l, params.qN.length, params.n)) {
			throw new IllegalArgumentException("invalid ct");
		}
	}
}

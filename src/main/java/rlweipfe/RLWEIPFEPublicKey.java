package rlweipfe;

import java.io.Serializable;

/**
 * Holds the public parameter a and master public key pk, both in NTT domain.
 */
public record RLWEIPFEPublicKey(int[][] a, int[][][] pk) implements Serializable {

	public void validate(RLWEIPFEParams params) {
		if(!Check.checkDims(a, params.qN.length, params.n)) {
			throw new IllegalArgumentException("invalid a");
		}
		if(!Check.checkDims(pk, params.l, params.qN.length, params.n)) {
			throw new IllegalArgumentException("invalid pk");
		}
	}
}

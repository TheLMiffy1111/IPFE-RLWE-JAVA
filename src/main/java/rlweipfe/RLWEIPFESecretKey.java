package rlweipfe;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Holds the master secret key sk.
 */
public record RLWEIPFESecretKey(int[][][] sk) implements Serializable {

	public void validate(RLWEIPFEParams params) {
		if(!Check.checkDims(sk, params.l, params.qN.length, params.n)) {
			throw new IllegalArgumentException("invalid sk");
		}
	}
}

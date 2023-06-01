package rlweipfebig;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Holds the master secret key sk.
 */
public record RLWEIPFEBSecretKey(BigInteger[][] sk) implements Serializable {

	public void validate(RLWEIPFEBParams params) {
		if(!CheckB.checkDims(sk, params.l, params.n)) {
			throw new IllegalArgumentException("invalid sk");
		}
	}
}

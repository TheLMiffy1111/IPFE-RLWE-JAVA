package rlweipfebig;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Holds the public parameter a and master public key pk, both in NTT domain.
 */
public record RLWEIPFEBPublicKey(BigInteger[] a, BigInteger[][] pk) implements Serializable {

	public void validate(RLWEIPFEBParams params) {
		if(!CheckB.checkDims(a, params.n)) {
			throw new IllegalArgumentException("invalid a");
		}
		if(!CheckB.checkDims(pk, params.l, params.n)) {
			throw new IllegalArgumentException("invalid pk");
		}
	}
}

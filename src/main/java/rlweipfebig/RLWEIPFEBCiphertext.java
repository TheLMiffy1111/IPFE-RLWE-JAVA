package rlweipfebig;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Holds the ciphertext ct0 and ct, and the size of the encrypted message.
 */
public record RLWEIPFEBCiphertext(int n, BigInteger[] ct0, BigInteger[][] ct) implements Serializable {

	public void validate(RLWEIPFEBParams params) {
		if(n > params.n) {
			throw new IllegalArgumentException("invalid n");
		}
		if(!CheckB.checkDims(ct0, params.n)) {
			throw new IllegalArgumentException("invalid ct0");
		}
		if(!CheckB.checkDims(ct, params.l, params.n)) {
			throw new IllegalArgumentException("invalid ct");
		}
	}
}

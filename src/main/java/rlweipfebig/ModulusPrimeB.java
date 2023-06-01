package rlweipfebig;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * A number that can be used in a modulus chain, with phi^2^exp = -1 mod q
 */
public record ModulusPrimeB(int exp, BigInteger q, BigInteger phi) implements Comparable<ModulusPrimeB>, Serializable {

	public ModulusPrimeB(int exp, BigInteger q, BigInteger phi) {
		this.exp = exp;
		this.q = q;
		this.phi = phi;
		// Check if phi is a valid root to the used polynomial
		if(!phi.modPow(BigInteger.valueOf(1 << exp), q).equals(q.subtract(BigInteger.ONE))) {
			throw new IllegalArgumentException("invalid phi");
		}
	}

	@Override
	public int compareTo(ModulusPrimeB o) {
		int a = Integer.compare(exp, o.exp);
		if(a != 0) {
			return a;
		}
		return q.compareTo(o.q);
	}

	public static ModulusPrimeB next(int exp, BigInteger qMin) {
		BigInteger inc = BigInteger.ONE.shiftLeft(exp+1);
		BigInteger q = qMin.shiftRight(exp+1).add(BigInteger.ONE).shiftLeft(exp+1).add(BigInteger.ONE);
		while(true) {
			o:if(q.isProbablePrime(100)) {
				BigInteger phi = q.subtract(BigInteger.ONE);
				for(int i = 0; i < exp; ++i) {
					phi = ArithB.modSqrt(phi, q);
					if(phi.equals(BigInteger.ZERO)) {
						break o;
					}
				}
				return new ModulusPrimeB(exp, q, phi);
			}
			q = q.add(inc);
		}
	}
}

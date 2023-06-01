package rlweipfebig;

import java.math.BigInteger;

/**
 * A helper class that pre-computes and holds convenient values based on the given modulus chain.
 */
public class ModulusB {

	public final int n;
	public final ModulusPrimeB prime;
	public final BigInteger q;
	public final BigInteger qDivK;
	public final BigInteger[] phis;
	public final BigInteger[] phiInvs;
	public final BigInteger nInv;

	public ModulusB(int exp, ModulusPrimeB prime, BigInteger k) {
		if(prime.exp() != exp) {
			throw new IllegalArgumentException("prime exponent does not match");
		}
		n = 1 << exp;
		this.prime = prime;
		this.q = prime.q();
		this.qDivK = q.divide(k);
		phis = new BigInteger[n];
		phiInvs = new BigInteger[n];
		BigInteger phi = prime.phi();
		BigInteger phiInv = phi.modInverse(q);
		BigInteger phiX = BigInteger.ONE;
		BigInteger phiInvX = BigInteger.ONE;
		for(int x = 0; x < n; ++x) {
			int revX = (Integer.reverse(x) >>> (32-exp));
			phis[revX] = phiX;
			phiInvs[revX] = phiInvX;
			phiX = phiX.multiply(phi).mod(q);
			phiInvX = phiInvX.multiply(phiInv).mod(q);
		}
		nInv = BigInteger.valueOf(n).modInverse(q);
	}
}

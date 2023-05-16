package rlweipfe;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * A helper class that pre-computes and holds convenient values based on the given modulus chain.
 */
public class Modulus {

	public final int n;
	public final ModulusPrime[] primes;
	public final BigInteger value;
	public final BigDecimal qDivK;
	public final int[][] phis;
	public final int[][] phiInvs;
	public final int[] nInvs;
	public final int[] cs;
	public final int[] qDivKs;

	public Modulus(int exp, ModulusPrime[] primes, BigInteger k) {
		n = 1 << exp;
		Arrays.sort(primes);
		this.primes = primes;
		BigInteger value = BigInteger.ONE;
		phis = new int[primes.length][];
		phiInvs = new int[primes.length][];
		nInvs = new int[primes.length];
		qDivKs = new int[primes.length];
		cs = new int[primes.length];
		for(int i = 0; i < primes.length; ++i) {
			ModulusPrime prime = primes[i];
			if(prime.exp() != exp) {
				throw new IllegalArgumentException("prime exponent does not match");
			}
			BigInteger qI = prime.qBigInt();
			value = value.multiply(qI);
			int[] phiI = new int[n];
			int[] phiInvI = new int[n];
			BigInteger phi = prime.phiBigInt();
			BigInteger phiInv = phi.modInverse(qI);
			BigInteger phiX = BigInteger.ONE;
			BigInteger phiInvX = BigInteger.ONE;
			for(int x = 0; x < n; ++x) {
				int revX = (Integer.reverse(x) >>> (32-exp));
				phiI[revX] = phiX.intValueExact();
				phiInvI[revX] = phiInvX.intValueExact();
				phiX = phiX.multiply(phi).mod(qI);
				phiInvX = phiInvX.multiply(phiInv).mod(qI);
			}
			phis[i] = phiI;
			phiInvs[i] = phiInvI;
			nInvs[i] = BigInteger.valueOf(n).modInverse(qI).intValueExact();
			if(i > 0) {
				BigInteger c = BigInteger.ONE;
				for(int j = 0; j < i; ++j) {
					c = c.multiply(primes[j].qBigInt().modInverse(qI)).mod(qI);
				}
				cs[i] = c.intValueExact();
			}
		}
		this.value = value;
		BigInteger qDivK = value.divide(k);
		for(int i = 0; i < primes.length; ++i) {
			BigInteger qI = primes[i].qBigInt();
			qDivKs[i] = qDivK.mod(qI).intValueExact();
		}
		this.qDivK = new BigDecimal(qDivK);
	}
}

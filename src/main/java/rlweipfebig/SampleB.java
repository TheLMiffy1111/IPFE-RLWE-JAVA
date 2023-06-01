package rlweipfebig;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Methods to generate samples.
 */
public class SampleB {

	/**
	 * Generates uniform distribution samples using Java's implementation.
	 * @param mod The modulus parameters to be used
	 * @param rand The random number generator to be used
	 * @return Samples from the uniform distribution with range (0, q)
	 */
	public static BigInteger[] uniform(ModulusB mod, SecureRandom rand) {
		BigInteger[] arr = new BigInteger[mod.n];
		for(int i = 0; i < mod.n; ++i) {
			arr[i] = nextBigInt(rand, BigInteger.ONE, mod.q);
		}
		return arr;
	}

	static BigInteger nextBigInt(Random rand, BigInteger origin, BigInteger bound) {
		if(origin.compareTo(bound) > 0) {
			throw new IllegalArgumentException("bound must be greater than origin");
		}
		BigInteger n = bound.subtract(origin);
		if(n.bitCount() == 1) {
			return new BigInteger(n.bitLength()-1, rand).add(origin);
		}
		else {
			BigInteger r;
			do {
				r = new BigInteger(n.bitLength(), rand);
			}
			while(r.compareTo(n) >= 0);
			return r.add(origin);
		}
	}

	/**
	 * Generates normal distribution samples using Java's implementation.
	 * This seems to work as well as the FACCT scheme and is faster.
	 * @param mod The modulus parameters to be used
	 * @param sigma The standard deviation to be used
	 * @param rand The random number generator to be used
	 * @return Samples from the normal distribution with standard deviation sigma centered on 0
	 */
	public static BigInteger[] normal(ModulusB mod, double sigma, SecureRandom rand) {
		BigInteger[] arr = new BigInteger[mod.n];
		BigDecimal sigmaD = new BigDecimal(sigma);
		for(int i = 0; i < mod.n; ++i) {
			arr[i] = new BigDecimal(rand.nextGaussian(0, 1)).
					multiply(sigmaD).
					setScale(0, RoundingMode.HALF_EVEN).
					toBigIntegerExact().
					mod(mod.q);
		}
		return arr;
	}
}

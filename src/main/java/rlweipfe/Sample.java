package rlweipfe;

import java.security.SecureRandom;

/**
 * Methods to generate samples.
 */
public class Sample {

	static final long[][] CDT_TABLE = {
			{2200310400551559144L, 3327841033070651387L},
			{7912151619254726620L, 380075531178589176L},
			{5167367257772081627L, 11604843442081400L},
			{5081592746475748971L, 90134450315532L},
			{6522074513864805092L, 175786317361L},
			{2579734681240182346L, 85801740L},
			{8175784047440310133L, 10472L},
			{2947787991558061753L, 0L},
			{22489665999543L, 0L}
	};
	static final int CDT_LEN = 9;
	static final long CDT_LOW_MASK = 0x7FFFFFFFFFFFFFFFL;
	// sqrt(2ln2)
	static final double INV_SIGMA_CDT = 1.1774100225154747;
	// coefficients of polynomial approximating 2^x
	static final double[] EXP_COEF = {
			1.432910037894391E-7,
			1.2303944375555413E-6,
			1.5359914219462012E-5,
			1.5396043210538638E-4,
			0.0013333877552501097,
			0.009618120933175645,
			0.05550410984131825,
			0.24022650687652775,
			0.6931471805619338,
			1.0};
	static final int MANTISSA_PRECISION = 52;
	static final long MANTISSA_MASK = (1L << MANTISSA_PRECISION) - 1;
	static final int SAMPLE_BIT_LEN = 72 - MANTISSA_PRECISION - 1;
	static final long MAX_EXP = 1023;

	/**
	 * Generates uniform distribution samples using Java's implementation.
	 * @param mod The modulus parameters to be used
	 * @param rand The random number generator to be used
	 * @return Samples from the uniform distribution with range (0, q)
	 */
	public static int[][] uniform(Modulus mod, SecureRandom rand) {
		int[][] arr = new int[mod.primes.length][mod.n];
		for(int i = 0; i < mod.primes.length; ++i) {
			int q = mod.primes[i].q();
			for(int j = 0; j < mod.n; ++j) {
				arr[i][j] = rand.nextInt(1, q);
			}
		}
		return arr;
	}

	/**
	 * Generates normal distribution samples using Java's implementation.
	 * This seems to work as well as the FACCT scheme and is faster.
	 * @param mod The modulus parameters to be used
	 * @param sigma The standard deviation to be used
	 * @param rand The random number generator to be used
	 * @return Samples from the normal distribution with standard deviation sigma centered on 0
	 */
	public static int[][] normal(Modulus mod, double sigma, SecureRandom rand) {
		int[][] arr = new int[mod.primes.length][mod.n];
		for(int j = 0; j < mod.n; ++j) {
			long val = Math.round(rand.nextGaussian(0, sigma));
			for(int i = 0; i < mod.primes.length; ++i) {
				arr[i][j] = Math.floorMod(val, mod.primes[i].q());
			}
		}
		return arr;
	}

	/**
	 * Generates normal distribution samples using the FACCT scheme.
	 * @param mod The modulus parameters to be used
	 * @param sigma The standard deviation to be used
	 * @param rand The random number generator to be used
	 * @return Samples from the normal distribution with standard deviation sigma centered on 0
	 */
	public static int[][] normalFACCT(Modulus mod, double sigma, SecureRandom rand) {
		long k = Math.round(sigma*INV_SIGMA_CDT);
		double k2Inv = 1./k/k;
		int[][] arr = new int[mod.primes.length][mod.n];
		for(int j = 0; j < mod.n; ++j) {
			long val = normalFACCT(k, k2Inv, rand);
			for(int i = 0; i < mod.primes.length; ++i) {
				arr[i][j] = Math.floorMod(val, mod.primes[i].q());
			}
		}
		return arr;
	}

	public static long normalFACCT(long k, double k2Inv, SecureRandom rand) {
		while(true) {
			long x = normalCDT(rand);
			long y = rand.nextLong(k);
			int sign = rand.nextBoolean() ? 1 : -1;
			long res = x*k;
			long checkVal = (res*2 + y)*y;
			res += y;
			boolean check = bernoulli(checkVal, k2Inv, rand);
			if(check & (res > 0 | sign == -1)) {
				return res*sign;
			}
		}
	}

	static long normalCDT(SecureRandom rand) {
		long r1 = rand.nextLong() & CDT_LOW_MASK;
		long r2 = rand.nextLong() & CDT_LOW_MASK;
		long x = 0;
		for(int i = 0; i < CDT_LEN; ++i) {
			x += (((r1 - CDT_TABLE[i][0]) & ((1L << 63) ^ ((r2 - CDT_TABLE[i][1]) | (CDT_TABLE[i][1] - r2)))) | (r2 - CDT_TABLE[i][1])) >>> 63;
		}
		return x;
	}

	static boolean bernoulli(long t, double lSquareInv, SecureRandom rand) {
		double a = -t*lSquareInv;
		double negFloorA = -Math.floor(a);
		double z = a + negFloorA;
		double powOfZ = EXP_COEF[0];
		for(int i = 1; i < 10; ++i) {
			powOfZ = powOfZ*z + EXP_COEF[i];
		}
		long powOfZBits = Double.doubleToRawLongBits(powOfZ);
		long powOfAMantissa = powOfZBits & MANTISSA_MASK;
		long powOfAExponent = (powOfZBits >>> MANTISSA_PRECISION) - (long)negFloorA;
		long r1 = (rand.nextLong() >>> (64 - MANTISSA_PRECISION - 1));
		long r2 = (rand.nextLong() >>> (64 - SAMPLE_BIT_LEN));
		long check1 = powOfAMantissa | (1L << MANTISSA_PRECISION);
		long check2 = 1L << (SAMPLE_BIT_LEN + powOfAExponent + 1 - MAX_EXP);
		return r1 < check1 & r2 < check2 || powOfZ == 1;
	}
}

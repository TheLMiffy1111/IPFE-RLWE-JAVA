package rlweipfe;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Operations related to NTT, CRT, and arithmetic under a modulus.
 * <p>
 * NTT based on
 * "Speeding up the Number Theoretic Transform for Faster Ideal Lattice-Based Cryptography"
 * by Patrick Longa and Michael Naehrig,
 * see https://eprint.iacr.org/2016/504
 */
public class Arith {

	/**
	 * @return a = NTT(a, mod[sel])
	 */
	public static int[] forwardNTT(int[] a, Modulus mod, int sel) {
		if(a.length != mod.n) {
			throw new IllegalArgumentException("vector is of wrong size");
		}
		int q = mod.primes[sel].q();
		int[] phi = mod.phis[sel];
		int t = mod.n;
		for(int m = 1; m < mod.n; m *= 2) {
			t /= 2;
			for(int i = 0; i < m; ++i) {
				int j1 = 2*i*t;
				int j2 = j1+t;
				int S = phi[m+i];
				for(int j = j1; j < j2; ++j){
					int U = a[j];
					int V = mul(a[j+t], S, q);
					a[j] = add(U, V, q);
					a[j+t] = sub(U, V, q);
				}
			}
		}
		return a;
	}

	/**
	 * @return NTT(a, mod[sel])
	 */
	public static int[] forwardNTTCopy(int[] a, Modulus mod, int sel) {
		return forwardNTT(Arrays.copyOf(a, mod.n), mod, sel);
	}

	/**
	 * @return a = INTT(a, mod[sel])
	 */
	public static int[] inverseNTT(int[] a, Modulus mod, int sel) {
		if(a.length != mod.n) {
			throw new IllegalArgumentException("vector is of wrong size");
		}
		int q = mod.primes[sel].q();
		int[] phiInv = mod.phiInvs[sel];
		int t = 1;
		for(int m = mod.n; m > 1; m /= 2) {
			int j1 = 0;
			int h = m/2;
			for(int i = 0; i < h; ++i) {
				int j2 = j1+t;
				int S = phiInv[h+i];
				for(int j = j1; j < j2; ++j){
					int U = a[j];
					int V = a[j+t];
					a[j] = add(U, V, q);
					a[j+t] = sub(U, V, q);
					a[j+t] = mul(a[j+t], S, q);
				}
				j1 = j1+2*t;
			}
			t *= 2;
		}
		int nInv = mod.nInvs[sel];
		for(int i = 0; i < mod.n; ++i) {
			a[i] = mul(a[i], nInv, q);
		}
		return a;
	}

	/**
	 * @return INTT(a, mod[sel])
	 */
	public static int[] inverseNTTCopy(int[] a, Modulus mod, int sel) {
		return inverseNTT(Arrays.copyOf(a, mod.n), mod, sel);
	}

	/**
	 * @return a = cconv(a, b) % mod(sel)
	 */
	public static int[] polyNTTMulAssign(int[] a, int[] b, Modulus mod, int sel) {
		if(a.length != mod.n) {
			throw new IllegalArgumentException("vector is of wrong size");
		}
		forwardNTT(a, mod, sel);
		b = forwardNTTCopy(b, mod, sel);
		vecPointMulAssign(a, b, mod, sel);
		return inverseNTT(a, mod, sel);
	}

	/**
	 * @return cconv(a, b) % mod(sel)
	 */
	public static int[] polyNTTMul(int[] a, int[] b, Modulus mod, int sel) {
		return polyNTTMulAssign(Arrays.copyOf(a, mod.n), b, mod, sel);
	}

	/**
	 * @return a = a+b % mod(sel)
	 */
	public static int[] vecAddAssign(int[] a, int[] b, Modulus mod, int sel) {
		if(a.length < b.length) {
			throw new IllegalArgumentException("vector sizes do not match");
		}
		int q = mod.primes[sel].q();
		for(int i = 0; i < b.length; ++i) {
			a[i] = add(a[i], b[i], q);
		}
		return a;
	}

	/**
	 * @return a+b % mod(sel)
	 */
	public static int[] vecAdd(int[] a, int[] b, Modulus mod, int sel) {
		return vecAddAssign(a.clone(), b, mod, sel);
	}

	/**
	 * @return a = a+b % mod(sel)
	 */
	public static int[] vecAddAssign(int[] a, int b, Modulus mod, int sel) {
		int q = mod.primes[sel].q();
		for(int i = 0; i < a.length; ++i) {
			a[i] = add(a[i], b, q);
		}
		return a;
	}

	/**
	 * @return a+b % mod(sel)
	 */
	public static int[] vecAdd(int[] a, int b, Modulus mod, int sel) {
		return vecAddAssign(a.clone(), b, mod, sel);
	}

	/**
	 * @return a = a-b % mod(sel)
	 */
	public static int[] vecSubAssign(int[] a, int[] b, Modulus mod, int sel) {
		if(a.length < b.length) {
			throw new IllegalArgumentException("vector sizes do not match");
		}
		int q = mod.primes[sel].q();
		for(int i = 0; i < b.length; ++i) {
			a[i] = sub(a[i], b[i], q);
		}
		return a;
	}

	/**
	 * @return a-b % mod(sel)
	 */
	public static int[] vecSub(int[] a, int[] b, Modulus mod, int sel) {
		return vecSubAssign(a.clone(), b, mod, sel);
	}

	/**
	 * @return a = a-b % mod(sel)
	 */
	public static int[] vecSubAssign(int[] a, int b, Modulus mod, int sel) {
		int q = mod.primes[sel].q();
		for(int i = 0; i < a.length; ++i) {
			a[i] = sub(a[i], b, q);
		}
		return a;
	}

	/**
	 * @return a-b % mod(sel)
	 */
	public static int[] vecSub(int[] a, int b, Modulus mod, int sel) {
		return vecSubAssign(a.clone(), b, mod, sel);
	}

	/**
	 * @return a = a.*b % mod(sel)
	 */
	public static int[] vecPointMulAssign(int[] a, int[] b, Modulus mod, int sel) {
		if(a.length < b.length) {
			throw new IllegalArgumentException("vector sizes do not match");
		}
		int q = mod.primes[sel].q();
		for(int i = 0; i < b.length; ++i) {
			a[i] = mul(a[i], b[i], q);
		}
		return a;
	}

	/**
	 * @return a.*b % mod(sel)
	 */
	public static int[] vecPointMul(int[] a, int[] b, Modulus mod, int sel) {
		return vecPointMulAssign(a.clone(), b, mod, sel);
	}

	/**
	 * @return a = a*b % mod(sel)
	 */
	public static int[] vecMulAssign(int[] a, int b, Modulus mod, int sel) {
		int q = mod.primes[sel].q();
		for(int i = 0; i < a.length; ++i) {
			a[i] = mul(a[i], b, q);
		}
		return a;
	}

	/**
	 * @return a*b % mod(sel)
	 */
	public static int[] vecMul(int[] a, int b, Modulus mod, int sel) {
		return vecMulAssign(a.clone(), b, mod, sel);
	}

	public static int[][] vecForwardCRT(int[] x, Modulus mod) {
		int[][] xCRT = new int[mod.primes.length][x.length];
		for(int i = 0; i < mod.primes.length; ++i) {
			int q = mod.primes[i].q();
			for(int j = 0; j < x.length; ++j) {
				xCRT[i][j] = Math.floorMod(x[j], q);
			}
		}
		return xCRT;
	}

	public static int[][] vecForwardCRT(BigInteger[] x, Modulus mod) {
		int[][] xCRT = new int[mod.primes.length][x.length];
		for(int i = 0; i < mod.primes.length; ++i) {
			BigInteger q = mod.primes[i].qBigInt();
			for(int j = 0; j < x.length; ++j) {
				xCRT[i][j] = x[j].mod(q).intValueExact();
			}
		}
		return xCRT;
	}

	public static BigInteger[] vecInverseCRT(int[][] xCRT, Modulus mod) {
		if(xCRT.length != mod.primes.length) {
			throw new IllegalArgumentException("crt sequence is of wrong size");
		}
		BigInteger[] x = new BigInteger[xCRT[0].length];
		Arrays.fill(x, BigInteger.ZERO);
		for(int i = 0; i < xCRT[0].length; ++i) {
			x[i] = BigInteger.valueOf(xCRT[0][i]);
			BigInteger c = mod.primes[0].qBigInt();
			for(int j = 1; j < mod.primes.length; ++j) {
				if(xCRT[j].length != xCRT[0].length) {
					throw new IllegalArgumentException("crt sequence is jagged");
				}
				x[i] = BigInteger.valueOf(xCRT[j][i]).
						subtract(x[i]).
						multiply(BigInteger.valueOf(mod.cs[j])).
						mod(mod.primes[j].qBigInt()).
						multiply(c).
						add(x[i]);
				c = c.multiply(mod.primes[j].qBigInt());
			}
			if(x[i].compareTo(c.shiftRight(1)) >= 0) {
				x[i] = x[i].subtract(c);
			}
		}
		return x;
	}

	public static BigInteger dot(int[] a, int[] b) {
		if(a.length != b.length) {
			throw new IllegalArgumentException("vector sizes do not match");
		}
		BigInteger c = BigInteger.ZERO;
		for(int i = 0; i < a.length; ++i) {
			c = c.add(BigInteger.valueOf(a[i]).multiply(BigInteger.valueOf(b[i])));
		}
		return c;
	}

	public static int add(int a, int b, int q) {
		return Math.floorMod(Integer.toUnsignedLong(a)+Integer.toUnsignedLong(b), q);
	}

	public static int sub(int a, int b, int q) {
		return Math.floorMod(Integer.toUnsignedLong(a)-Integer.toUnsignedLong(b), q);
	}

	public static int mul(int a, int b, int q) {
		return Math.floorMod(Integer.toUnsignedLong(a)*Integer.toUnsignedLong(b), q);
	}
}

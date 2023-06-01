package rlweipfebig;

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
public class ArithB {

	/**
	 * @return a = NTT(a, mod.q)
	 */
	public static BigInteger[] forwardNTT(BigInteger[] a, ModulusB mod) {
		if(a.length != mod.n) {
			throw new IllegalArgumentException("vector is of wrong size");
		}
		int t = mod.n;
		for(int m = 1; m < mod.n; m *= 2) {
			t /= 2;
			for(int i = 0; i < m; ++i) {
				int j1 = 2*i*t;
				int j2 = j1+t;
				BigInteger S = mod.phis[m+i];
				for(int j = j1; j < j2; ++j){
					BigInteger U = a[j];
					BigInteger V = mul(a[j+t], S, mod.q);
					a[j] = add(U, V, mod.q);
					a[j+t] = sub(U, V, mod.q);
				}
			}
		}
		return a;
	}

	/**
	 * @return NTT(a, mod.q)
	 */
	public static BigInteger[] forwardNTTCopy(BigInteger[] a, ModulusB mod) {
		return forwardNTT(Arrays.copyOf(a, mod.n), mod);
	}

	/**
	 * @return a = INTT(a, mod.q)
	 */
	public static BigInteger[] inverseNTT(BigInteger[] a, ModulusB mod) {
		if(a.length != mod.n) {
			throw new IllegalArgumentException("vector is of wrong size");
		}
		int t = 1;
		for(int m = mod.n; m > 1; m /= 2) {
			int j1 = 0;
			int h = m/2;
			for(int i = 0; i < h; ++i) {
				int j2 = j1+t;
				BigInteger S = mod.phiInvs[h+i];
				for(int j = j1; j < j2; ++j){
					BigInteger U = a[j];
					BigInteger V = a[j+t];
					a[j] = add(U, V, mod.q);
					a[j+t] = sub(U, V, mod.q);
					a[j+t] = mul(a[j+t], S, mod.q);
				}
				j1 = j1+2*t;
			}
			t *= 2;
		}
		for(int i = 0; i < mod.n; ++i) {
			a[i] = mul(a[i], mod.nInv, mod.q);
		}
		return a;
	}

	/**
	 * @return INTT(a, mod.q)
	 */
	public static BigInteger[] inverseNTTCopy(BigInteger[] a, ModulusB mod) {
		return inverseNTT(Arrays.copyOf(a, mod.n), mod);
	}

	/**
	 * @return a = cconv(a, b) % mod.q
	 */
	public static BigInteger[] polyNTTMulAssign(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		if(a.length != mod.n) {
			throw new IllegalArgumentException("vector is of wrong size");
		}
		forwardNTT(a, mod);
		b = forwardNTTCopy(b, mod);
		vecPointMulAssign(a, b, mod);
		return inverseNTT(a, mod);
	}

	/**
	 * @return cconv(a, b) % mod.q
	 */
	public static BigInteger[] polyNTTMul(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		return polyNTTMulAssign(Arrays.copyOf(a, mod.n), b, mod);
	}

	/**
	 * @return a = a+b % mod.q
	 */
	public static BigInteger[] vecAddAssign(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		if(a.length < b.length) {
			throw new IllegalArgumentException("vector sizes do not match");
		}
		for(int i = 0; i < b.length; ++i) {
			a[i] = add(a[i], b[i], mod.q);
		}
		return a;
	}

	/**
	 * @return a+b % mod.q
	 */
	public static BigInteger[] vecAdd(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		return vecAddAssign(a.clone(), b, mod);
	}

	/**
	 * @return a = a+b % mod.q
	 */
	public static BigInteger[] vecAddAssign(BigInteger[] a, BigInteger b, ModulusB mod) {
		for(int i = 0; i < a.length; ++i) {
			a[i] = add(a[i], b, mod.q);
		}
		return a;
	}

	/**
	 * @return a+b % mod.q
	 */
	public static BigInteger[] vecAdd(BigInteger[] a, BigInteger b, ModulusB mod) {
		return vecAddAssign(a.clone(), b, mod);
	}

	/**
	 * @return a = a-b % mod.q
	 */
	public static BigInteger[] vecSubAssign(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		if(a.length < b.length) {
			throw new IllegalArgumentException("vector sizes do not match");
		}
		for(int i = 0; i < b.length; ++i) {
			a[i] = sub(a[i], b[i], mod.q);
		}
		return a;
	}

	/**
	 * @return a-b % mod.q
	 */
	public static BigInteger[] vecSub(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		return vecSubAssign(a.clone(), b, mod);
	}

	/**
	 * @return a = a-b % mod.q
	 */
	public static BigInteger[] vecSubAssign(BigInteger[] a, BigInteger b, ModulusB mod) {
		for(int i = 0; i < a.length; ++i) {
			a[i] = sub(a[i], b, mod.q);
		}
		return a;
	}

	/**
	 * @return a-b % mod.q
	 */
	public static BigInteger[] vecSub(BigInteger[] a, BigInteger b, ModulusB mod) {
		return vecSubAssign(a.clone(), b, mod);
	}

	/**
	 * @return a = a.*b % mod.q
	 */
	public static BigInteger[] vecPointMulAssign(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		if(a.length < b.length) {
			throw new IllegalArgumentException("vector sizes do not match");
		}
		for(int i = 0; i < b.length; ++i) {
			a[i] = mul(a[i], b[i], mod.q);
		}
		return a;
	}

	/**
	 * @return a.*b % mod.q
	 */
	public static BigInteger[] vecPointMul(BigInteger[] a, BigInteger[] b, ModulusB mod) {
		return vecPointMulAssign(a.clone(), b, mod);
	}

	/**
	 * @return a = a*b % mod.q
	 */
	public static BigInteger[] vecMulAssign(BigInteger[] a, BigInteger b, ModulusB mod) {
		for(int i = 0; i < a.length; ++i) {
			a[i] = mul(a[i], b, mod.q);
		}
		return a;
	}

	/**
	 * @return a*b % mod.q
	 */
	public static BigInteger[] vecMul(BigInteger[] a, BigInteger b, ModulusB mod) {
		return vecMulAssign(a.clone(), b, mod);
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

	public static BigInteger add(BigInteger a, BigInteger b, BigInteger q) {
		return a.add(b).mod(q);
	}

	public static BigInteger sub(BigInteger a, BigInteger b, BigInteger q) {
		return a.subtract(b).mod(q);
	}

	public static BigInteger mul(BigInteger a, BigInteger b, BigInteger q) {
		return a.multiply(b).mod(q);
	}

	public static BigInteger modSqrt(BigInteger n, BigInteger p) {
		try {
			n = n.mod(p);
			BigInteger s = BigInteger.ZERO;
			BigInteger q = p.subtract(BigInteger.ONE);
			while(q.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
				s = s.add(BigInteger.ONE);
				q = q.shiftRight(1);
			}
			if(s.equals(BigInteger.ONE)) {
				BigInteger r = n.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
				return mul(r, r, p).equals(n) ? r : BigInteger.ZERO;
			}
			BigInteger z = BigInteger.TWO;
			while(!z.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(p.subtract(BigInteger.ONE))) {
				z = z.add(BigInteger.ONE);
			}
			BigInteger c = z.modPow(q, p);
			BigInteger r = n.modPow(q.add(BigInteger.ONE).shiftRight(1), p);
			BigInteger t = n.modPow(q, p);
			BigInteger m = s;
			while(!t.equals(BigInteger.ONE)) {
				BigInteger u = t;
				BigInteger i = BigInteger.ZERO;
				while(!u.equals(BigInteger.ONE)) {
					u = mul(u, u, p);
					i = i.add(BigInteger.ONE);
					if(i.equals(m)) {
						return BigInteger.ZERO;
					}
				}
				BigInteger b = c;
				BigInteger e = m.subtract(i).subtract(BigInteger.ONE);
				while(e.compareTo(BigInteger.ZERO) > 0) {
					b = mul(b, b, p);
					e = e.subtract(BigInteger.ONE);
				}
				r = mul(r, b, p);
				c = mul(b, b, p);
				t = mul(t, c, p);
				m = i;
			}
			return mul(r, r, p).equals(n) ? r : BigInteger.ZERO;
		}
		catch(Exception e) {
			return BigInteger.ZERO;
		}
	}
}

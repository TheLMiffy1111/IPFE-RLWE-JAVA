package rlweipfe;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;

/**
 * Implements a selectively secure inner product functional encryption scheme
 * based on the ring learning with errors assumption.
 * The scheme allows encryption of a vector/matrix x and derive a function key based on a vector y
 * so that one can decrypt x^T * y and nothing else.
 * <p>
 * Based on
 * "Efficient Lattice-Based Inner-Product Functional Encryption"
 * by Jose Maria Bermudo Mera, Angshuman Karmakar, Tilen Marc, and Azam Soleimanian,
 * see https://eprint.iacr.org/2021/046
 */
public class RLWEIPFE {

	public final RLWEIPFEParams params;

	/**
	 * Constructs an instance of the scheme with the
	 * @param params The parameters of the scheme
	 */
	public RLWEIPFE(RLWEIPFEParams params) {
		this.params = params;
	}

	/**
	 * @param rand The random number generator to be used
	 * @return The master secret key
	 */
	public RLWEIPFESecretKey generateSecretKey(SecureRandom rand) {
		int[][][] sk = new int[params.l][][];
		for(int i = 0; i < params.l; ++i) {
			sk[i] = Sample.normal(params.q(), params.s1, rand);
		}
		return new RLWEIPFESecretKey(sk);
	}

	/**
	 * @param msk The master secret key
	 * @param rand The random number generator to be used
	 * @return The master public key
	 */
	public RLWEIPFEPublicKey generatePublicKey(RLWEIPFESecretKey msk, SecureRandom rand) {
		msk.validate(params);
		Modulus mod = params.q();
		int[][] a = Sample.uniform(mod, rand);
		int[][][] pk = new int[params.l][mod.primes.length][];
		for(int i = 0; i < params.l; ++i) {
			int[][] e = Sample.normal(mod, params.s1, rand);
			for(int j = 0; j < mod.primes.length; ++j) {
				int[] mskNTT = Arith.forwardNTTCopy(msk.sk()[i][j], mod, j);
				Arith.forwardNTT(e[j], mod, j);
				pk[i][j] = Arith.vecPointMul(a[j], mskNTT, mod, j);
				Arith.vecAddAssign(pk[i][j], e[j], mod, j);
			}
		}
		return new RLWEIPFEPublicKey(a, pk);
	}

	/**
	 * @param y The vector to find the inner product with the encrypted vector/matrix x
	 * @param msk The master secret key
	 * @return The secret function key associated with y
	 */
	public RLWEIPFEFunctionKey deriveFunctionKey(int[] y, RLWEIPFESecretKey msk) {
		if(!Check.checkDims(y, params.l)) {
			throw new IllegalArgumentException("invalid y");
		}
		msk.validate(params);
		Modulus mod = params.q();
		int[][] yCRT = Arith.vecForwardCRT(y, mod);
		int[][] skY = new int[mod.primes.length][params.n];
		for(int j = 0; j < mod.primes.length; ++j) {
			int q = mod.primes[j].q();
			for(int i = 0; i < params.l; ++i) {
				for(int k = 0; k < params.n; ++k) {
					int mac = Arith.mul(yCRT[j][i], msk.sk()[i][j][k], q);
					skY[j][k] = Arith.add(skY[j][k], mac, q);
				}
			}
		}
		return new RLWEIPFEFunctionKey(yCRT, skY);
	}

	/**
	 * @param x The vector x to be encrypted
	 * @param mpk The master public key
	 * @param rand The random number generator to be used
	 * @return The encrypted ciphertext associated with x
	 */
	public RLWEIPFECiphertext encryptSingle(int[] x, RLWEIPFEPublicKey mpk, SecureRandom rand) {
		if(!Check.checkDims(x, params.l)) {
			throw new IllegalArgumentException("invalid x");
		}
		mpk.validate(params);
		Modulus mod = params.q();
		int[][] xCRT = Arith.vecForwardCRT(x, mod);
		for(int j = 0; j < mod.primes.length; ++j) {
			int q = mod.primes[j].q();
			int qDivK = mod.qDivKs[j];
			for(int i = 0; i < params.l; ++i) {
				xCRT[j][i] = Arith.mul(xCRT[j][i], qDivK, q);
			}
		}
		int[][] r = Sample.normal(mod, params.s2, rand);
		int[][] f = Sample.normal(mod, params.s2, rand);
		int[][] ct0 = new int[mod.primes.length][];
		int[][][] ct = new int[params.l][mod.primes.length][];
		for(int i = 0; i < mod.primes.length; ++i) {
			Arith.forwardNTT(r[i], mod, i);
			ct0[i] = Arith.vecPointMul(mpk.a()[i], r[i], mod, i);
			Arith.inverseNTT(ct0[i], mod, i);
			Arith.vecAddAssign(ct0[i], f[i], mod, i);
		}
		for(int i = 0; i < params.l; ++i) {
			f = Sample.normal(mod, params.s3, rand);
			for(int j = 0; j < mod.primes.length; ++j) {
				ct[i][j] = Arith.vecPointMul(mpk.pk()[i][j], r[j], mod, j);
				Arith.inverseNTT(ct[i][j], mod, j);
				Arith.vecAddAssign(ct[i][j], f[j], mod, j);
				Arith.vecAddAssign(ct[i][j], xCRT[j][i], mod, j);
			}
		}
		return new RLWEIPFECiphertext(1, ct0, ct);
	}

	/**
	 * @param x The matrix x to be encrypted
	 * @param mpk The master public key
	 * @param rand The random number generator to be used
	 * @return The encrypted ciphertext associated with x
	 */
	public RLWEIPFECiphertext encryptMulti(int[][] x, RLWEIPFEPublicKey mpk, SecureRandom rand) {
		if(x.length > params.n) {
			throw new IllegalArgumentException("invalid x");
		}
		mpk.validate(params);
		Modulus mod = params.q();
		int[][][] xCRT = new int[params.l][mod.primes.length][params.n];
		for(int k = 0; k < x.length; ++k) {
			int[] xK = x[k];
			if(xK.length != params.l) {
				throw new IllegalArgumentException("invalid x");
			}
			int[][] xKCRT = Arith.vecForwardCRT(xK, mod);
			for(int j = 0; j < mod.primes.length; ++j) {
				int q = mod.primes[j].q();
				int qDivK = mod.qDivKs[j];
				for(int i = 0; i < params.l; ++i) {
					xCRT[i][j][k] = Arith.mul(xKCRT[j][i], qDivK, q);
				}
			}
		}
		int[][] r = Sample.normal(mod, params.s2, rand);
		int[][] f = Sample.normal(mod, params.s2, rand);
		int[][] ct0 = new int[mod.primes.length][];
		int[][][] ct = new int[params.l][mod.primes.length][];
		for(int i = 0; i < mod.primes.length; ++i) {
			Arith.forwardNTT(r[i], mod, i);
			ct0[i] = Arith.vecPointMul(mpk.a()[i], r[i], mod, i);
			Arith.inverseNTT(ct0[i], mod, i);
			Arith.vecAddAssign(ct0[i], f[i], mod, i);
		}
		for(int i = 0; i < params.l; ++i) {
			f = Sample.normal(mod, params.s3, rand);
			for(int j = 0; j < mod.primes.length; ++j) {
				ct[i][j] = Arith.vecPointMul(mpk.pk()[i][j], r[j], mod, j);
				Arith.inverseNTT(ct[i][j], mod, j);
				Arith.vecAddAssign(ct[i][j], f[j], mod, j);
				Arith.vecAddAssign(ct[i][j], xCRT[i][j], mod, j);
			}
		}
		return new RLWEIPFECiphertext(x.length, ct0, ct);
	}

	/**
	 * @param ct The encrypted ciphertext associated with vector/matrix x 
	 * @param skY The The secret function key associated with vector y
	 * @return y * x^T
	 */
	public BigInteger[] decrypt(RLWEIPFECiphertext ct, RLWEIPFEFunctionKey skY) {
		ct.validate(params);
		skY.validate(params);
		Modulus mod = params.q();
		int[][] dY = new int[mod.primes.length][params.n];
		for(int j = 0; j < mod.primes.length; ++j) {
			int q = mod.primes[j].q();
			for(int i = 0; i < params.l; ++i) {
				for(int k = 0; k < ct.n(); ++k) {
					int mac = Arith.mul(ct.ct()[i][j][k], skY.y()[j][i], q);
					dY[j][k] = Arith.add(dY[j][k], mac, q);
				}
			}
		}
		for(int i = 0; i < mod.primes.length; ++i) {
			int[] c0sy = Arith.polyNTTMul(ct.ct0()[i], skY.skY()[i], mod, i);
			Arith.vecSubAssign(dY[i], c0sy, mod, i);
		}
		BigInteger[] xy = Arith.vecInverseCRT(dY, mod);
		BigInteger[] xyR = new BigInteger[ct.n()];
		for(int i = 0; i < ct.n(); ++i) {
			xyR[i] = new BigDecimal(xy[i]).divide(mod.qDivK, RoundingMode.HALF_EVEN).toBigIntegerExact();
		}
		return xyR;
	}

	/**
	 * @param ct The encrypted ciphertext associated with vector/matrix x 
	 * @param msk The master secret key
	 * @return x
	 */
	public int[][] decryptAll(RLWEIPFECiphertext ct, RLWEIPFESecretKey msk) {
		ct.validate(params);
		msk.validate(params);
		Modulus mod = params.q();
		int[][][] d = new int[params.l][mod.primes.length][];
		for(int j = 0; j < mod.primes.length; ++j) {
			int q = mod.primes[j].q();
			for(int i = 0; i < params.l; ++i) {
				int[] c0s = Arith.polyNTTMul(ct.ct0()[j], msk.sk()[i][j], mod, j);
				d[i][j] = Arith.vecSub(ct.ct()[i][j], c0s, mod, j);
			}
		}
		BigInteger[][] x = new BigInteger[params.l][];
		int[][] xR = new int[ct.n()][params.l];
		for(int i = 0; i < params.l; ++i) {
			x[i] = Arith.vecInverseCRT(d[i], mod);
		}
		for(int i = 0; i < ct.n(); ++i) {
			for(int j = 0; j < params.l; ++j) {
				xR[i][j] = new BigDecimal(x[j][i]).divide(mod.qDivK, RoundingMode.HALF_EVEN).intValueExact();
			}
		}
		return xR;
	}

	/**
	 * @param sec The security parameter
	 * @param l The length of the vector or number of columns of the matrix to be encrypted
	 * @param n The number of rows of the matrix to be encrypted.
	 * @param bx The expected maximum norm of the matrix x
	 * @param by The expected maximum norm of the vector y
	 * @return An instance of the scheme with a set of parameters that satisfy the constraints
	 */
	public static RLWEIPFE generate(int sec, int l, int n, int bx, int by) {
		return new RLWEIPFE(RLWEIPFEParams.generate(sec, l, n, bx, by));
	}
}

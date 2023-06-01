package rlweipfebig;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.Arrays;

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
public class RLWEIPFEB {

	public final RLWEIPFEBParams params;

	/**
	 * Constructs an instance of the scheme with the
	 * @param params The parameters of the scheme
	 */
	public RLWEIPFEB(RLWEIPFEBParams params) {
		this.params = params;
	}

	/**
	 * @param rand The random number generator to be used
	 * @return The master secret key
	 */
	public RLWEIPFEBSecretKey generateSecretKey(SecureRandom rand) {
		BigInteger[][] sk = new BigInteger[params.l][];
		for(int i = 0; i < params.l; ++i) {
			sk[i] = SampleB.normal(params.q(), params.s1, rand);
		}
		return new RLWEIPFEBSecretKey(sk);
	}

	/**
	 * @param msk The master secret key
	 * @param rand The random number generator to be used
	 * @return The master public key
	 */
	public RLWEIPFEBPublicKey generatePublicKey(RLWEIPFEBSecretKey msk, SecureRandom rand) {
		msk.validate(params);
		ModulusB mod = params.q();
		BigInteger[] a = SampleB.uniform(mod, rand);
		BigInteger[][] pk = new BigInteger[params.l][];
		for(int i = 0; i < params.l; ++i) {
			BigInteger[] e = SampleB.normal(mod, params.s1, rand);
			BigInteger[] mskNTT = ArithB.forwardNTTCopy(msk.sk()[i], mod);
			ArithB.forwardNTT(e, mod);
			pk[i] = ArithB.vecPointMul(a, mskNTT, mod);
			ArithB.vecAddAssign(pk[i], e, mod);
		}
		return new RLWEIPFEBPublicKey(a, pk);
	}

	/**
	 * @param y The vector to find the inner product with the encrypted vector/matrix x
	 * @param msk The master secret key
	 * @return The secret function key associated with y
	 */
	public RLWEIPFEBFunctionKey deriveFunctionKey(int[] y, RLWEIPFEBSecretKey msk) {
		if(!CheckB.checkDims(y, params.l)) {
			throw new IllegalArgumentException("invalid y");
		}
		msk.validate(params);
		ModulusB mod = params.q();
		BigInteger[] yB = Arrays.stream(y).mapToObj(BigInteger::valueOf).map(i->i.mod(mod.q)).toArray(BigInteger[]::new);
		BigInteger[] skY = new BigInteger[params.n];
		Arrays.fill(skY, BigInteger.ZERO);
		for(int i = 0; i < params.l; ++i) {
			for(int j = 0; j < params.n; ++j) {
				BigInteger mac = ArithB.mul(yB[i], msk.sk()[i][j], mod.q);
				skY[j] = ArithB.add(skY[j], mac, mod.q);
			}
		}
		return new RLWEIPFEBFunctionKey(yB, skY);
	}

	/**
	 * @param x The vector x to be encrypted
	 * @param mpk The master public key
	 * @param rand The random number generator to be used
	 * @return The encrypted ciphertext associated with x
	 */
	public RLWEIPFEBCiphertext encryptSingle(int[] x, RLWEIPFEBPublicKey mpk, SecureRandom rand) {
		if(!CheckB.checkDims(x, params.l)) {
			throw new IllegalArgumentException("invalid x");
		}
		mpk.validate(params);
		ModulusB mod = params.q();
		BigInteger[] xB = Arrays.stream(x).mapToObj(BigInteger::valueOf).map(i->i.mod(mod.q)).toArray(BigInteger[]::new);
		BigInteger qDivK = mod.qDivK;
		for(int i = 0; i < params.l; ++i) {
			xB[i] = ArithB.mul(xB[i], qDivK, mod.q);
		}
		BigInteger[] r = SampleB.normal(mod, params.s2, rand);
		BigInteger[] f = SampleB.normal(mod, params.s2, rand);
		BigInteger[] ct0;
		BigInteger[][] ct = new BigInteger[params.l][];
		ArithB.forwardNTT(r, mod);
		ct0 = ArithB.vecPointMul(mpk.a(), r, mod);
		ArithB.inverseNTT(ct0, mod);
		ArithB.vecAddAssign(ct0, f, mod);
		for(int i = 0; i < params.l; ++i) {
			f = SampleB.normal(mod, params.s3, rand);
			ct[i] = ArithB.vecPointMul(mpk.pk()[i], r, mod);
			ArithB.inverseNTT(ct[i], mod);
			ArithB.vecAddAssign(ct[i], f, mod);
			ArithB.vecAddAssign(ct[i], xB[i], mod);
		}
		return new RLWEIPFEBCiphertext(1, ct0, ct);
	}

	/**
	 * @param x The matrix x to be encrypted
	 * @param mpk The master public key
	 * @param rand The random number generator to be used
	 * @return The encrypted ciphertext associated with x
	 */
	public RLWEIPFEBCiphertext encryptMulti(int[][] x, RLWEIPFEBPublicKey mpk, SecureRandom rand) {
		if(x.length > params.n) {
			throw new IllegalArgumentException("invalid x");
		}
		mpk.validate(params);
		ModulusB mod = params.q();
		BigInteger[][] xB = new BigInteger[params.l][params.n];
		for(int i = 0; i < params.l; ++i) {
			Arrays.fill(xB[i], BigInteger.ZERO);
		}
		for(int j = 0; j < x.length; ++j) {
			int[] xJ = x[j];
			if(xJ.length != params.l) {
				throw new IllegalArgumentException("invalid x");
			}
			BigInteger[] xJB = Arrays.stream(xJ).mapToObj(BigInteger::valueOf).map(i->i.mod(mod.q)).toArray(BigInteger[]::new);
			BigInteger qDivK = mod.qDivK;
			for(int i = 0; i < params.l; ++i) {
				xB[i][j] = ArithB.mul(xJB[i], qDivK, mod.q);
			}
		}
		BigInteger[] r = SampleB.normal(mod, params.s2, rand);
		BigInteger[] f = SampleB.normal(mod, params.s2, rand);
		BigInteger[] ct0;
		BigInteger[][] ct = new BigInteger[params.l][];
		ArithB.forwardNTT(r, mod);
		ct0 = ArithB.vecPointMul(mpk.a(), r, mod);
		ArithB.inverseNTT(ct0, mod);
		ArithB.vecAddAssign(ct0, f, mod);
		for(int i = 0; i < params.l; ++i) {
			f = SampleB.normal(mod, params.s3, rand);
			ct[i] = ArithB.vecPointMul(mpk.pk()[i], r, mod);
			ArithB.inverseNTT(ct[i], mod);
			ArithB.vecAddAssign(ct[i], f, mod);
			ArithB.vecAddAssign(ct[i], xB[i], mod);
		}
		return new RLWEIPFEBCiphertext(x.length, ct0, ct);
	}

	/**
	 * @param ct The encrypted ciphertext associated with vector/matrix x 
	 * @param skY The The secret function key associated with vector y
	 * @return y * x^T
	 */
	public BigInteger[] decrypt(RLWEIPFEBCiphertext ct, RLWEIPFEBFunctionKey skY) {
		ct.validate(params);
		skY.validate(params);
		ModulusB mod = params.q();
		BigInteger[] dY = new BigInteger[params.n];
		Arrays.fill(dY, BigInteger.ZERO);
		for(int i = 0; i < params.l; ++i) {
			for(int j = 0; j < ct.n(); ++j) {
				BigInteger mac = ArithB.mul(ct.ct()[i][j], skY.y()[i], mod.q);
				dY[j] = ArithB.add(dY[j], mac, mod.q);
			}
		}
		BigInteger[] c0sy = ArithB.polyNTTMul(ct.ct0(), skY.skY(), mod);
		ArithB.vecSubAssign(dY, c0sy, mod);
		BigInteger[] xyR = new BigInteger[ct.n()];
		BigDecimal qDivKD = new BigDecimal(mod.qDivK);
		for(int i = 0; i < ct.n(); ++i) {
			if(dY[i].compareTo(mod.q.shiftRight(1)) >= 0) {
				dY[i] = dY[i].subtract(mod.q);
			}
			xyR[i] = new BigDecimal(dY[i]).divide(qDivKD, RoundingMode.HALF_EVEN).toBigIntegerExact();
		}
		return xyR;
	}

	/**
	 * @param ct The encrypted ciphertext associated with vector/matrix x 
	 * @param msk The master secret key
	 * @return x
	 */
	public int[][] decryptAll(RLWEIPFEBCiphertext ct, RLWEIPFEBSecretKey msk) {
		ct.validate(params);
		msk.validate(params);
		ModulusB mod = params.q();
		BigInteger[][] d = new BigInteger[params.l][];
		for(int i = 0; i < params.l; ++i) {
			BigInteger[] c0s = ArithB.polyNTTMul(ct.ct0(), msk.sk()[i], mod);
			d[i] = ArithB.vecSub(ct.ct()[i], c0s, mod);
		}
		int[][] xR = new int[ct.n()][params.l];
		BigDecimal qDivKD = new BigDecimal(mod.qDivK);
		for(int i = 0; i < ct.n(); ++i) {
			for(int j = 0; j < params.l; ++j) {
				if(d[j][i].compareTo(mod.q.shiftRight(1)) >= 0) {
					d[j][i] = d[j][i].subtract(mod.q);
				}
				xR[i][j] = new BigDecimal(d[j][i]).divide(qDivKD, RoundingMode.HALF_EVEN).intValueExact();
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
	public static RLWEIPFEB generate(int sec, int l, int n, int bx, int by) {
		return new RLWEIPFEB(RLWEIPFEBParams.generate(sec, l, n, bx, by));
	}
}

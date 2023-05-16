package rlweipfe;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;

/**
 * Holds the parameters of the encryption scheme.
 */
public class RLWEIPFEParams implements Serializable {

	private static final double SQRT_2 = Math.sqrt(2);

	public final int l;
	public final int exp;
	public final int n;
	public final int bx;
	public final int by;
	public final BigInteger k;
	public final ModulusPrime[] qN;
	public final double s1;
	public final double s2;
	public final double s3;
	private transient Modulus q;

	/**
	 * @param l Length of data vectors for inner product
	 * @param exp log2(n)
	 * @param n The degree of the polynomial used in the scheme
	 * @param bx Bound of the maximum norm of the matrix x
	 * @param by Bound of the maximum norm of the vector y
	 * @param k Bound of the resulting inner product
	 * @param qN The modulus chain used
	 * @param s1 Standard deviation used for master key generation
	 * @param s2 Standard deviation used for public parameter encryption
	 * @param s3 Standard deviation used for data encryption
	 */
	public RLWEIPFEParams(int l, int exp, int n, int bx, int by, BigInteger k, ModulusPrime[] qN, double s1, double s2, double s3) {
		this.l = l;
		this.exp = exp;
		this.n = n;
		this.bx = bx;
		this.by = by;
		this.k = k;
		this.qN = qN;
		this.s1 = s1;
		this.s2 = s2;
		this.s3 = s3;
		q = new Modulus(exp, qN, k);
	}

	@Serial
	private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
		ois.defaultReadObject();
		q = new Modulus(exp, qN, k);
	}

	public Modulus q() {
		return q;
	}

	/**
	 * @param sec The security parameter
	 * @param l The length of the vector or number of columns of the matrix x to be encrypted
	 * @param n The number of rows of the matrix to be encrypted.
	 * @param bx Bound of the maximum norm of the matrix x
	 * @param by Bound of the maximum norm of the vector y
	 * @return A set of parameters that satisfy the constraints
	 */
	public static RLWEIPFEParams generate(int sec, int l, int n, int bx, int by) {
		BigInteger k = BigInteger.TWO.
				multiply(BigInteger.valueOf(l)).
				multiply(BigInteger.valueOf(bx)).
				multiply(BigInteger.valueOf(by)).
				add(BigInteger.ONE);
		double secSqrt = Math.sqrt(sec);
		double sigma = 1;
		double sigma1 = 2*Math.sqrt(l)*bx*sigma;
		int bBound = (int)(sec/0.265);

		int exp = Math.max(32-Integer.numberOfLeadingZeros(n-1), 6);
		double sigma2 = 0;
		double sigma3 = 0;
		BigInteger q = BigInteger.ONE;
		ModulusPrime[] qN = new ModulusPrime[0];
		for(; exp < 20; ++exp) {
			n = 1 << exp;
			sigma2 = SQRT_2*Math.sqrt(l+2)*n*sigma1*secSqrt*sigma;
			sigma3 = sigma2*SQRT_2;

			BigInteger qMin = BigDecimal.valueOf(2).
					multiply(BigDecimal.valueOf(n)).
					multiply(BigDecimal.valueOf(sec)).
					multiply(BigDecimal.valueOf(sigma1)).
					multiply(BigDecimal.valueOf(sigma2)).
					add(BigDecimal.valueOf(secSqrt).multiply(BigDecimal.valueOf(sigma3))).
					toBigInteger().
					shiftLeft(1).	
					multiply(k);
			Map.Entry<BigInteger, ModulusPrime[]> entry = ModulusPrime.getPrimes(exp, qMin);
			q = entry.getKey();
			qN = entry.getValue();

			// Check if parameters are safe against primal attack
			double qF = q.doubleValue();
			boolean safe = true;
			for(int b = 50; b <= bBound; ++b) {
				for(int m = Math.max(1, b-n); m < 3*n; ++m) {
					double delta = Math.pow(Math.pow(Math.PI*b, 1/b)*b/(2*Math.PI*Math.E), 1./(2*b-2));
					double left = sigma*Math.sqrt(b);
					int d = n+m;
					double right = Math.pow(delta, 2*b-d-1)*Math.pow(qF, (double)m/d);
					if(left <= right) {
						safe = false;
						break;
					}
				}
				if(!safe) {
					break;
				}
			}
			if(safe) {
				break;
			}
		}
		return new RLWEIPFEParams(
				l, exp, n, bx, by, k, qN, sigma1, sigma2, sigma3
				);
	}

	@Override
	public String toString() {
		return "RLWEIPFEParams [l=%s, exp=%s, n=%s, bx=%s, by=%s, k=%s, qN=%s, s1=%s, s2=%s, s3=%s]".
				formatted(l, exp, n, bx, by, k, Arrays.toString(qN), s1, s2, s3);
	}
}

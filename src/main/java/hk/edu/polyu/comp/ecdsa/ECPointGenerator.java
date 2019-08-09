package hk.edu.polyu.comp.ecdsa;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import hk.edu.polyu.comp.ecdsa.math.EcUtil;
import hk.edu.polyu.comp.util.Hash;

public class ECPointGenerator extends ECHelper {

	public final BigInteger A;
	public final BigInteger B;
	public final BigInteger P;

	public ECPointGenerator(ECDomainParameters ec, BigInteger a, BigInteger b, BigInteger p) {
		super(ec);
		this.A = a;
		this.B = b;
		this.P = p;
	}

	private BigInteger[] computeCoordinate(BigInteger x) {
		BigInteger y = findY(x);
		while (y == null) {
			byte[] xByte = Hash.sha256(x.toByteArray());
			x = new BigInteger(1, xByte).mod(P);
			y = findY(x);
		}
		return new BigInteger[] { x, y };
	}

	private BigInteger findY(BigInteger x) {
		try {
			BigInteger y = x.multiply(x).multiply(x).add(x.multiply(A)).add(B);
			return EcUtil.modSqrt(y, P);
		} catch (GeneralSecurityException e) {
			return null;
		}
	}

	public boolean judgeX(BigInteger x) {
		return findY(x) != null;
	}

	public ECPoint generate(byte[] chosen, int signum) {
		byte[] xByte = Hash.sha256(chosen);
		BigInteger[] coord;
		BigInteger x = new BigInteger(1, xByte).mod(P);
		BigInteger y;
		coord = computeCoordinate(x);
		x = coord[0];
		y = coord[1];
		if (signum < 0) {
			y = P.subtract(y);
		}
		x = ec.getCurve().fromBigInteger(x).toBigInteger();
		y = ec.getCurve().fromBigInteger(y).toBigInteger();

		ECPoint ret = ec.getCurve().createPoint(x, y);		
		return ret;
	}
}

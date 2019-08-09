package hk.edu.polyu.comp.ecdsa;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECConvertor {

	public static BigInteger privateKeyToBigInteger(ECPrivateKey sk) {
		return sk.getS();
	}

	public static ECPoint publicKeyToECPoint(ECCurve curve, ECPublicKey pk) {
		BigInteger x = pk.getW().getAffineX();
		BigInteger y = pk.getW().getAffineY();
		return curve.createPoint(x, y);
	}

	public static ECPoint publicKeyToECPoint(ECCurve curve, byte[] encoded) {
		return curve.decodePoint(encoded);
	}
}

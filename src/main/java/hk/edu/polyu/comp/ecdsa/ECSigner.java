package hk.edu.polyu.comp.ecdsa;

import java.math.BigInteger;

import javax.xml.ws.Holder;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public class ECSigner extends ECHelper {

	public ECSigner(ECDomainParameters ec) {
		super(ec);
	}

	public BigInteger[] sign(BigInteger privateKey, byte[] message) {
		return sign(privateKey, message, null, null);
	}

	public BigInteger[] sign(BigInteger privateKey, byte[] message, Holder<ECPoint> R, Holder<BigInteger> k) {
		BigInteger h = new BigInteger(1, hash(message));
		BigInteger r;
		BigInteger s;

		if (R == null) {
			R = new Holder<ECPoint>();
		}
		if(k == null) {
			k = new  Holder<BigInteger>();
		}

		do {
			do {
				k.value = randomNumber();
				R.value = G.multiply(k.value).normalize();
				r = R.value.getAffineXCoord().toBigInteger().mod(N);
			} while (ZERO.equals(r));

			s = k.value.modInverse(N).multiply(h.add(privateKey.multiply(r))).mod(N);
		} while (ZERO.equals(s));

		return new BigInteger[] { r, s };
	}

	public boolean verify(ECPoint publicKey, byte[] message, BigInteger r, BigInteger s) {
		if (r.compareTo(ONE) < 0 || r.compareTo(N) >= 0) {
			return false;
		}
		if (s.compareTo(ONE) < 0 || s.compareTo(N) >= 0) {
			return false;
		}

		BigInteger h = new BigInteger(1, hash(message));
		BigInteger s1 = s.modInverse(N);

		BigInteger n1 = h.multiply(s1).mod(N);
		BigInteger n2 = r.multiply(s1).mod(N);

		ECPoint R = G.multiply(n1).add(publicKey.multiply(n2));
		BigInteger r1 = R.normalize().getAffineXCoord().toBigInteger().mod(N);

		return r.equals(r1);
	}
}

package hk.edu.polyu.comp.bcct;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import hk.edu.polyu.comp.ecdsa.ECProtocal;

public class ECBitEncrypter extends ECProtocal {

	public ECBitEncrypter(ECDomainParameters ec, ECPoint g1, ECPoint g2) {
		super(ec, g1, g2);
	}

	public ECBitCypher encrypt(ECPoint publicKey, BigInteger x, BigInteger y) {
		ECPoint g1 = G1.multiply(x);
		ECPoint g2 = G2.multiply(y);
		ECPoint u = g1.add(g2);
		ECPoint v = publicKey.multiply(y);
		return new ECBitCypher(u, v);
	}

	public ECPoint decrypt(BigInteger privateKey, ECPoint u, ECPoint v) {
		ECPoint vt = v.multiply(privateKey.modInverse(N));
		ECPoint result = u.subtract(vt);
		return result;
	}

}

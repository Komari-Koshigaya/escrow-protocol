package hk.edu.polyu.comp.ecdsa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import hk.edu.polyu.comp.DebugUtils;
import hk.edu.polyu.comp.bcct.ECBitCypher;
import hk.edu.polyu.comp.bcct.ECBitEncrypter;
import hk.edu.polyu.comp.ecdsa.bitcoin.BitcoinUtils;
import hk.edu.polyu.comp.util.BinaryUtils;
import hk.edu.polyu.comp.util.Random;

public class EcdsaBasicTest {

	static final BigInteger N = Secp256k1.N;

	@Test
	public void testECConvertor() throws Exception {
		// PK to ECPoint convertion
		KeyPair keypair = Secp256k1.generateKeyPair(null);

		ECPrivateKey sk = (ECPrivateKey) keypair.getPrivate();
		BigInteger d = sk.getS();
		ECPoint pk = Secp256k1.G.multiply(d);

		ECPoint converedPk1 = ECConvertor.publicKeyToECPoint(Secp256k1.CURVE, (ECPublicKey) keypair.getPublic());
		assertEquals(pk, converedPk1);

		ECPoint converedPk2 = ECConvertor.publicKeyToECPoint(Secp256k1.CURVE, pk.getEncoded(true));
		assertEquals(pk, converedPk2);
	}

	@Test
	public void testECSigner() throws Exception {
		KeyPair keypair1 = Secp256k1.generateKeyPair("1".getBytes());
		BigInteger sk1 = ECConvertor.privateKeyToBigInteger((ECPrivateKey) keypair1.getPrivate());
		ECPoint pk1 = ECConvertor.publicKeyToECPoint(Secp256k1.CURVE, (ECPublicKey) keypair1.getPublic());
		byte[] m1 = "testing1".getBytes();
		BigInteger[] sig1 = Secp256k1.generateSignature(sk1, m1);

		KeyPair keypair2 = Secp256k1.generateKeyPair("2".getBytes());
		BigInteger sk2 = ECConvertor.privateKeyToBigInteger((ECPrivateKey) keypair2.getPrivate());
		ECPoint pk2 = ECConvertor.publicKeyToECPoint(Secp256k1.CURVE, (ECPublicKey) keypair2.getPublic());
		byte[] m2 = "testing2".getBytes();
		BigInteger[] sig2 = Secp256k1.generateSignature(sk2, m2);

		boolean result1 = Secp256k1.verifySignature(pk1, m1, sig1[0], sig1[1]);
		boolean result2 = Secp256k1.verifySignature(pk2, m1, sig1[0], sig1[1]);
		boolean result3 = Secp256k1.verifySignature(pk1, m2, sig1[0], sig1[1]);
		boolean result4 = Secp256k1.verifySignature(pk1, m1, sig2[0], sig1[1]);
		boolean result5 = Secp256k1.verifySignature(pk1, m1, sig1[0], sig2[1]);
		boolean result6 = Secp256k1.verifySignature(pk2, m2, sig2[0], sig2[1]);

		DebugUtils.print("sk 1", BinaryUtils.encodeHex(sk1.toByteArray()));
		DebugUtils.print("sk 1", BitcoinUtils.encodePrivateKey(sk1, BitcoinUtils.VERSION_TESTNET));
		DebugUtils.print("sk 2", BinaryUtils.encodeHex(sk2.toByteArray()));
		DebugUtils.print("sk 2", BitcoinUtils.encodePrivateKey(sk2, BitcoinUtils.VERSION_TESTNET));

		assertTrue(result1);
		assertFalse(result2);
		assertFalse(result3);
		assertFalse(result4);
		assertFalse(result5);
		assertTrue(result6);
	}

	@Test
	public void testECPointGenerator() {
		ECPointGenerator gen = new ECPointGenerator(Secp256k1.DOMAIN_PARAMS, Secp256k1.A, Secp256k1.B, Secp256k1.P);
		ECPoint G = Secp256k1.G;
		ECPoint H = gen.generate(Random.generateRandomBytes(Secp256k1.N), 1);

		assertTrue(G.isValid());
		assertTrue(H.isValid());
		assertEquals(G.getCurve(), H.getCurve());
		assertTrue(G.multiply(N).isInfinity());
		assertTrue(H.multiply(N).isInfinity());

	}

	@Test
	public void testEncryptDecrypt() {
		ECPointGenerator gen = new ECPointGenerator(Secp256k1.DOMAIN_PARAMS, Secp256k1.A, Secp256k1.B, Secp256k1.P);
		ECPoint g2 = gen.generate("g2".getBytes(), 1);
		ECBitEncrypter encrypter = new ECBitEncrypter(Secp256k1.DOMAIN_PARAMS, Secp256k1.G, g2);

		BigInteger sk = BigInteger.valueOf(1234);
		ECPoint pk = g2.multiply(sk);

		BigInteger x = BigInteger.valueOf(1);
		BigInteger y = BigInteger.valueOf(2);
		ECPoint gx = Secp256k1.G.multiply(x);
		ECBitCypher cypher = encrypter.encrypt(pk, x, y);
		ECPoint result = encrypter.decrypt(sk, cypher.u, cypher.v);

		assertEquals(gx, result);
	}
	
	@Test
	public void testECOperationSpeed() {
		List<BigInteger> nums = new ArrayList<BigInteger>();
		List<ECPoint> points = new ArrayList<ECPoint>();
		
		for(int i = 0; i < 101; i++) {
			BigInteger num = Random.generateRandomNumber(N);
			nums.add(num);
			points.add(Secp256k1.G.multiply(num));
		}
		
		DebugUtils.timerStart("EC Add");
		for(int i = 0; i < 100; i++) {
			ECPoint ret = points.get(i).add(points.get(i+1));;
		}
		DebugUtils.timerEnd("EC Add");
		
		DebugUtils.timerStart("EC Mul");
		for(int i = 0; i < 100; i++) {
			ECPoint ret = points.get(i).multiply(nums.get(i));
		}
		DebugUtils.timerEnd("EC Mul");
		
		DebugUtils.timerStart("EC Inv");
		for(int i = 0; i < 100; i++) {
			ECPoint ret = points.get(i).multiply(BigInteger.ONE.modInverse(Secp256k1.N));	
		}
		DebugUtils.timerEnd("EC Inv");
	}
}

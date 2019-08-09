package hk.edu.polyu.comp.bcct;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import hk.edu.polyu.comp.DebugUtils;
import hk.edu.polyu.comp.bcct.OptimisticFairExchange;
import hk.edu.polyu.comp.bcct.EncryptedSignature;
import hk.edu.polyu.comp.ecdsa.Secp256k1;
import hk.edu.polyu.comp.util.BinaryUtils;
import hk.edu.polyu.comp.util.Hash;
import hk.edu.polyu.comp.util.Random;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.List;

import javax.xml.ws.Holder;

public class OptimisticFairExchangeTest {

	static final ECPoint g1 = Secp256k1.G;
	static final ECPoint g2 = Secp256k1.EC_POINT_GEN.generate("g2".getBytes(), 1);
	
	static final ECBitEncrypter enc = new ECBitEncrypter(Secp256k1.DOMAIN_PARAMS, g1, g2);
	
	static final OptimisticFairExchange ofe = new OptimisticFairExchange(Secp256k1.DOMAIN_PARAMS, g1, g2);
	
	@Test
	public void testSignatureRecovery() {
		// Alice keypair on point G1
		BigInteger sk = BigInteger.valueOf(1234);
		ECPoint pk = Secp256k1.G.multiply(sk);

		// Trusted party keypari on poing G2
		BigInteger tsk = BigInteger.valueOf(5678);
		ECPoint tpk = g2.multiply(tsk);

		byte[] message = BigInteger.valueOf(1234567890).toByteArray();

		// Encrypt and restore signature
		EncryptedSignature partSign = ofe.generateSignature(sk, tpk, message);

		DebugUtils.timerStart("Restore Signature");
		BigInteger[] recoverSign = ofe.restoreSignature(tsk, partSign);
		DebugUtils.timerEnd("Restore Signature");
		
		boolean isValid = Secp256k1.EC_SIGNER.verify(pk, message, recoverSign[0], recoverSign[1]);
		assertTrue(isValid);
		
	}

	@Test
	public void testPi1Proof() {
		// Trusted party keypari on poing G2
		BigInteger tsk = BigInteger.valueOf(5678);
		ECPoint tpk = g2.multiply(tsk);

		BigInteger x = Random.generateRandomNumber(Secp256k1.N);

		BigInteger ai = BigInteger.ONE;
		BigInteger ri = Random.generateRandomNumber(Secp256k1.N);
		ECBitCypher ci = enc.encrypt(tpk, ai, ri);

		BigInteger pAi = Random.generateRandomNumber(Secp256k1.N);
		BigInteger pRi = Random.generateRandomNumber(Secp256k1.N);
		BigInteger pi = Random.generateRandomNumber(Secp256k1.N);

		ECBitCypher ci1 = enc.encrypt(tpk, pAi, pRi);
		ECBitCypher ci2 = enc.encrypt(tpk, ai.multiply(pAi).mod(Secp256k1.N), pi);
		BigInteger zi1 = ai.multiply(x).add(pAi).mod(Secp256k1.N);
		BigInteger zi2 = ri.multiply(x).add(pRi).mod(Secp256k1.N);
		BigInteger zi3 = ri.multiply(x.subtract(zi1).mod(Secp256k1.N)).add(pi).mod(Secp256k1.N);

		ECBitCypher ci1_1 = enc.encrypt(tpk, zi1, zi2);
		ECBitCypher ci1_ = ci1_1.subtract(ci.multiply(x));
		ECBitCypher ci2_1 = enc.encrypt(tpk, BigInteger.ZERO, zi3);
		ECBitCypher ci2_ = ci2_1.subtract(ci.multiply(x.subtract(zi1).mod(Secp256k1.N)));

		assertEquals(ci1.u, ci1_.u);
		assertEquals(ci1.v, ci1_.v);
		assertEquals(ci2.u, ci2_.u);
		assertEquals(ci2.v, ci2_.v);
	}

	@Test
	public void testPi3Proof() {
		// Alice keypair on point G1
		BigInteger sk = BigInteger.valueOf(1234);
		ECPoint pk = Secp256k1.G.multiply(sk);

		// Trusted party keypari on poing G2
		BigInteger tsk = BigInteger.valueOf(5678);
		ECPoint tpk = g2.multiply(tsk);

		BigInteger x = BigInteger.valueOf(1234567890);
		byte[] message = x.toByteArray();

		// generate signature
		Holder<String> s = new Holder<String>();
		Holder<BigInteger> k = new Holder<BigInteger>();
		Holder<List<BigInteger>> riList = new Holder<List<BigInteger>>();
		EncryptedSignature signature = ofe.generateSignature(sk, tpk, message, s, k, riList);

		// test get U
		ECPoint U1 = ofe.getU(signature);

		BigInteger riSum = BigInteger.ZERO;
		int riSize = riList.value.size();
		for (int i = 0; i < riSize; i++) {
			BigInteger pow = ofe.pow2(riSize - i - 1);
			BigInteger ri = riList.value.get(i);
			riSum = riSum.add(ri.multiply(pow));
		}
		riSum = riSum.mod(ofe.N);

		ECPoint U2 = ofe.G1.multiply(new BigInteger(s.value, 2)).add(ofe.G2.multiply(riSum));
		assertEquals(U1, U2);

		// get gamma
		BigInteger gamma = ofe.getGamma(k.value, riList.value);

		// test get W
		ECPoint W1 = ofe.getW(U1, k.value, gamma);
		ECPoint W2 = ofe.getW(pk, message, signature.R);
		assertEquals(W1, W2);

		// test Y1, Y2
		BigInteger randPk = ofe.randomNumber();
		BigInteger randPy = ofe.randomNumber();

		ECPoint Y1 = ofe.G1.multiply(randPk);
		ECPoint Y2 = U1.multiply(randPk).add(ofe.G2.multiply(randPy));
		BigInteger z1 = randPk.subtract(x.multiply(k.value)).mod(ofe.N);
		BigInteger z2 = randPy.subtract(x.multiply(gamma)).mod(ofe.N);

		ECPoint Y1_ = signature.R.multiply(x).add(ofe.G1.multiply(z1));
		ECPoint Y2_ = W1.multiply(x).add(U1.multiply(z1)).add(ofe.G2.multiply(z2));

		assertEquals(Y1, Y1_);
		assertEquals(Y2, Y2_);
	}

	@Test
	public void testSignatureProof() {
		// Alice keypair on point G1
		BigInteger sk = BigInteger.valueOf(1234);
		ECPoint pk = Secp256k1.G.multiply(sk);

		// Trusted party keypari on poing G2
		BigInteger tsk = BigInteger.valueOf(5678);
		ECPoint tpk = g2.multiply(tsk);

		byte[] message = BigInteger.valueOf(1234567890).toByteArray();

		// generate signature proof
		DebugUtils.timerStart("Generate Signature Proof");
		SignatureProof proof = ofe.generateSignatureProof(sk, tpk, message);
		DebugUtils.timerEnd("Generate Signature Proof");

		assertEquals(proof.signature.cyphers.size(), proof.x.length());
		assertEquals(proof.signature.cyphers.size(), proof.zi1List.size());
		assertEquals(proof.signature.cyphers.size(), proof.zi2List.size());
		assertEquals(proof.signature.cyphers.size(), proof.zi3List.size());

		DebugUtils.print("size", proof.signature.cyphers.size());
		DebugUtils.print("R", proof.signature.R);
		
		DebugUtils.timerStart("Verify Signature Proof");
		boolean isValid = ofe.verifySignatureProof(pk, tpk, message, proof);
		DebugUtils.timerEnd("Verify Signature Proof");
		
		assertTrue(isValid);
	}

	@Test
	public void testSignature() throws DecoderException {
		// for testnet transaction
		// 9f43f84976f8de32a916d130eb94a1e9b2331af2ed6f06b7d73e13c0914bd762
		BigInteger s = new BigInteger("e18672c123c957da6478c808b2ec543ff1bbe376cd37e6d2929d9c2fa619b04", 16);
		BigInteger r = new BigInteger("34fa85319e903d27356b61a9443c06b6de1e65ce991caa629604cca3a5ab43d5", 16);
		
		// txStr is the sha256(tx input)
		String txStr = "c4142c1a962b9a2fab2fdd0016720f00c37b5bfd4511ed015f1e53b72a4694c1";
		byte[] tx = BinaryUtils.decodeHex(txStr);

		BigInteger sk = new BigInteger("e6cc90b878b948c35e92b003c792c46c58c4af40b46bd1a28085600ebde84ff7", 16);
		ECPoint pk = Secp256k1.G.multiply(sk);
		
		boolean isValid = Secp256k1.EC_SIGNER.verify(pk, tx, r, s);
		assertTrue(isValid);
	}
}

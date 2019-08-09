package hk.edu.polyu.comp.ecdsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import hk.edu.polyu.comp.util.Random;

import org.bouncycastle.math.ec.ECCurve;

//import hk.edu.polyu.comp.di.lib.PedersenCommitment;

public class Secp256k1 {

	static final ECGenParameterSpec EC_GEN_PARAMS_SPEC = new ECGenParameterSpec("secp256k1");

	static final KeyFactory KEY_FACTORY;

	static final KeyPairGenerator KEY_PAIR_GENERATOR;

	static final Signature SIGNATURE;

	static {
		// Add BC provider
		Security.addProvider(new BouncyCastleProvider());

		KeyFactory eckey = null;
		KeyPairGenerator eckeyGen = null;
		Signature sig = null;
		try {
			eckey = KeyFactory.getInstance("EC", "BC");
			eckeyGen = KeyPairGenerator.getInstance("EC", "BC");
			sig = Signature.getInstance("SHA256withECDSA", "BC");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		KEY_FACTORY = eckey;
		KEY_PAIR_GENERATOR = eckeyGen;
		SIGNATURE = sig;
	}

	public static final X9ECParameters EC_PARAMS = SECNamedCurves.getByName("secp256k1");

	public static final BigInteger A = BigInteger.valueOf(0);

	public static final BigInteger B = BigInteger.valueOf(7);

	public static final BigInteger P = new BigInteger(
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

	public static final BigInteger N = EC_PARAMS.getN();

	public static final ECPoint G = EC_PARAMS.getG();

	public static final ECCurve CURVE = EC_PARAMS.getCurve();

	public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G, N, EC_PARAMS.getH(),
			EC_PARAMS.getSeed());

	public static KeyPair generateKeyPair(byte[] seed) throws InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KEY_PAIR_GENERATOR;
		keyGen.initialize(EC_GEN_PARAMS_SPEC, Random.getRandomGenerator(seed));
		KeyPair keyPair = keyGen.genKeyPair();
		return keyPair;
	}

	public static byte[] generateSignature(PrivateKey key, byte[] data) throws InvalidKeyException, SignatureException {
		Signature ecdsa = SIGNATURE;
		SecureRandom random = new SecureRandom();
		ecdsa.initSign(key, random);
		ecdsa.update(data);
		return ecdsa.sign();
	}

	public static boolean verifySignature(PublicKey key, byte[] data, byte[] signature) {
		try {
			Signature ecdsa = SIGNATURE;
			ecdsa.initVerify(key);
			ecdsa.update(data);
			return ecdsa.verify(signature);
		} catch (Exception e) {
			return false;
		}
	}

	public static ECSigner EC_SIGNER = new ECSigner(DOMAIN_PARAMS);

	public static BigInteger[] generateSignature(BigInteger privateKey, byte[] message) {
		return EC_SIGNER.sign(privateKey, message);
	}

	public static boolean verifySignature(ECPoint publicKey, byte[] message, BigInteger r, BigInteger s) {
		return EC_SIGNER.verify(publicKey, message, r, s);
	}
	
	public static ECPointGenerator EC_POINT_GEN = new ECPointGenerator(DOMAIN_PARAMS, A, B, P);
}

package hk.edu.polyu.comp.bcct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.xml.ws.Holder;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import hk.edu.polyu.comp.ecdsa.ECProtocal;
import hk.edu.polyu.comp.ecdsa.ECSigner;
import hk.edu.polyu.comp.util.BinaryUtils;

public class OptimisticFairExchange extends ECProtocal {

	private final ECBitEncrypter EC_ENCRYPTER;
	private final ECSigner EC_SIGNER;

	public OptimisticFairExchange(ECDomainParameters ec, ECPoint g1, ECPoint g2) {
		super(ec, g1, g2);

		this.EC_ENCRYPTER = new ECBitEncrypter(ec, g1, g2);
		this.EC_SIGNER = new ECSigner(ec);
	}

	EncryptedSignature generateSignature(BigInteger privateKey, ECPoint trustedPartyPublicKey, byte[] message) {
		return generateSignature(privateKey, trustedPartyPublicKey, message, null, null, null);
	}

	EncryptedSignature generateSignature(BigInteger privateKey, ECPoint trustedPartyPublicKey, byte[] message,
			Holder<String> s, Holder<BigInteger> k, Holder<List<BigInteger>> riList) {
		if (s == null) {
			s = new Holder<String>();
		}
		if (k == null) {
			k = new Holder<BigInteger>();
		}
		if (riList == null) {
			riList = new Holder<List<BigInteger>>();
		}
		riList.value = new ArrayList<BigInteger>();

		Holder<ECPoint> R = new Holder<ECPoint>();
		BigInteger[] signature = EC_SIGNER.sign(privateKey, message, R, k);

		List<ECBitCypher> cs = new ArrayList<ECBitCypher>();
		String sBits = BinaryUtils.encodeBinary(signature[1].toByteArray());

		s.value = sBits;

		for (int i = 0; i < sBits.length(); i++) {
			BigInteger ri = randomNumber();
			BigInteger si = sBits.charAt(i) == '1' ? BigInteger.ONE : BigInteger.ZERO;
			riList.value.add(ri);
			cs.add(EC_ENCRYPTER.encrypt(trustedPartyPublicKey, si, ri));
		}
		return new EncryptedSignature(cs, R.value);
	}

	public ECPoint getU(EncryptedSignature signature) {
		ECPoint U = null;
		int size = signature.cyphers.size();
		for (int i = 0; i < size; i++) {
			ECPoint ui = signature.cyphers.get(i).u;
			BigInteger pow = pow2ModN(size - i - 1);
			ui = ui.multiply(pow);
			if (i == 0) {
				U = ui;
			} else {
				U = U.add(ui);
			}
		}
		return U;
	}

	public BigInteger getGamma(BigInteger k, List<BigInteger> riList) {
		int size = riList.size();
		BigInteger gamma = BigInteger.ZERO;
		for (int i = 0; i < size; i++) {
			BigInteger ri = riList.get(i);
			BigInteger pow = pow2(size - i - 1);
			BigInteger x = ri.multiply(pow);
			gamma = gamma.add(x);
		}
		gamma = gamma.multiply(k).negate().mod(N);
		return gamma;
	}

	public ECPoint getW(ECPoint publicKey, byte[] message, ECPoint R) {
		byte[] h_ = hash(message);
		BigInteger h = new BigInteger(1, h_);
		BigInteger r = R.normalize().getAffineXCoord().toBigInteger();
		return G1.multiply(h).add(publicKey.multiply(r));
	}

	public ECPoint getW(ECPoint U, BigInteger k, BigInteger gamma) {
		return U.multiply(k).add(G2.multiply(gamma));
	}

	public String getChallenge(ECPoint Y1, ECPoint Y2, List<ECBitCypher> ci1List, List<ECBitCypher> ci2List, int len) {
		try {
			ByteArrayOutputStream stream = new ByteArrayOutputStream();
			stream.write(Y1.getEncoded(true));
			stream.write(Y2.getEncoded(true));
			for (ECBitCypher c1 : ci1List) {
				stream.write(c1.u.getEncoded(true));
				stream.write(c1.v.getEncoded(true));
			}
			for (ECBitCypher c2 : ci2List) {
				stream.write(c2.u.getEncoded(true));
				stream.write(c2.v.getEncoded(true));
			}
			byte[] h = hash(stream.toByteArray());
			return BinaryUtils.encodeBinary(h, len);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public SignatureProof generateSignatureProof(BigInteger privateKey, ECPoint trustedPartyPublicKey, byte[] message) {
		SignatureProof proof = new SignatureProof();

		// Generate signature (keeps k, ri[], s)
		Holder<String> sBits = new Holder<String>();
		Holder<BigInteger> k = new Holder<BigInteger>();
		Holder<List<BigInteger>> riList = new Holder<List<BigInteger>>();
		proof.signature = generateSignature(privateKey, trustedPartyPublicKey, message, sBits, k, riList);

		// calculate U
		int size = proof.signature.cyphers.size();
		ECPoint U = getU(proof.signature);

		// calculate Y1, Y2
		BigInteger pk = randomNumber();
		BigInteger py = randomNumber();
		ECPoint Y1 = G1.multiply(pk);
		ECPoint Y2 = U.multiply(pk).add(G2.multiply(py));

		// calculate c1[], c2[]
		List<BigInteger> pAiList = new ArrayList<BigInteger>();
		List<BigInteger> pRiList = new ArrayList<BigInteger>();
		List<BigInteger> piList = new ArrayList<BigInteger>();
		List<ECBitCypher> ci1List = new ArrayList<ECBitCypher>();
		List<ECBitCypher> ci2List = new ArrayList<ECBitCypher>();

		for (int i = 0; i < size; i++) {
			BigInteger ai = sBits.value.charAt(i) == '1' ? ONE : ZERO;

			BigInteger pAi = randomNumber();
			BigInteger pRi = randomNumber();
			BigInteger pi = randomNumber();
			pAiList.add(pAi);
			pRiList.add(pRi);
			piList.add(pi);

			ci1List.add(EC_ENCRYPTER.encrypt(trustedPartyPublicKey, pAi, pRi));
			ci2List.add(EC_ENCRYPTER.encrypt(trustedPartyPublicKey, ai.multiply(pAi).mod(N), pi));
		}

		// calculate challenge
		proof.x = getChallenge(Y1, Y2, ci1List, ci2List, size);
		BigInteger x = new BigInteger(proof.x, 2);

		// calculate gamma, z1, z2
		BigInteger gamma = getGamma(k.value, riList.value);
		proof.z1 = pk.subtract(x.multiply(k.value)).mod(N);
		proof.z2 = py.subtract(x.multiply(gamma)).mod(N);

		// calculate zi1[], zi2[], zi3[]
		for (int i = 0; i < size; i++) {
			BigInteger ai = sBits.value.charAt(i) == '1' ? ONE : ZERO;
			BigInteger xi = new BigInteger(proof.x, 2);
			BigInteger ri = riList.value.get(i);
			BigInteger zi1 = ai.multiply(xi).add(pAiList.get(i)).mod(N);
			BigInteger zi2 = ri.multiply(xi).add(pRiList.get(i)).mod(N);
			BigInteger zi3 = ri.multiply(xi.subtract(zi1)).add(piList.get(i)).mod(N);
			proof.zi1List.add(zi1);
			proof.zi2List.add(zi2);
			proof.zi3List.add(zi3);
		}

		return proof;
	}

	public boolean verifySignatureProof(ECPoint publicKey, ECPoint trustedPartyPublicKey, byte[] message,
			SignatureProof proof) {
		byte[] _h = hash(message);
		BigInteger h = new BigInteger(1, _h);
		BigInteger r = proof.signature.R.normalize().getAffineXCoord().toBigInteger();
		ECPoint GhQr = G1.multiply(h).add(publicKey.multiply(r));

		BigInteger x = new BigInteger(proof.x, 2);

		int size = proof.signature.cyphers.size();

		List<ECBitCypher> ci1List = new ArrayList<ECBitCypher>();
		List<ECBitCypher> ci2List = new ArrayList<ECBitCypher>();
		for (int i = 0; i < size; i++) {
			ECBitCypher ci = proof.signature.cyphers.get(i);

			ECBitCypher zi12 = EC_ENCRYPTER.encrypt(trustedPartyPublicKey, proof.zi1List.get(i), proof.zi2List.get(i));
			ECBitCypher cix = ci.multiply(x);
			ci1List.add(zi12.subtract(cix));

			ECBitCypher zi03 = EC_ENCRYPTER.encrypt(trustedPartyPublicKey, ZERO, proof.zi3List.get(i));
			ECBitCypher cix_zi1 = ci.multiply(x.subtract(proof.zi1List.get(i)));
			ci2List.add(zi03.subtract(cix_zi1));
		}

		ECPoint U = getU(proof.signature);
		ECPoint W = GhQr;
		ECPoint Y1 = proof.signature.R.multiply(x).add(G1.multiply(proof.z1));
		ECPoint Y2 = W.multiply(x).add(U.multiply(proof.z1)).add(G2.multiply(proof.z2));

		String x1 = getChallenge(Y1, Y2, ci1List, ci2List, proof.signature.cyphers.size());

		return proof.x.equals(x1);
	}

	public BigInteger[] restoreSignature(BigInteger trustedPartyPrivateKey, EncryptedSignature signature) {
		BigInteger r = signature.R.normalize().getAffineXCoord().toBigInteger();
		StringBuilder sBits = new StringBuilder();
		for (int i = 0; i < signature.cyphers.size(); i++) {
			ECPoint decrypted = EC_ENCRYPTER.decrypt(trustedPartyPrivateKey, signature.cyphers.get(i).u,
					signature.cyphers.get(i).v);
			if (decrypted.equals(G1)) {
				sBits.append("1");
			} else {
				sBits.append("0");
			}
		}
		BigInteger s = new BigInteger(sBits.toString(), 2);
		return new BigInteger[] { r, s };
	}
}

package hk.edu.polyu.comp.ecdsa;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import hk.edu.polyu.comp.util.Hash;
import hk.edu.polyu.comp.util.Random;

public class ECHelper {

	protected static final BigInteger ONE = BigInteger.ONE;
	protected static final BigInteger ZERO = BigInteger.ZERO;

	public final ECDomainParameters ec;
	public final BigInteger N;
	public final ECPoint G;

	public ECHelper(ECDomainParameters ec) {
		super();
		this.ec = ec;
		this.N = ec.getN();
		this.G = ec.getG();
	}

	public byte[] hash(byte[] message) {
		byte[] h = Hash.sha256(message);
		return modN(h);
	}

	public byte[] modN(byte[] x) {
		x = new BigInteger(1, x).mod(N).toByteArray();
		return x.length == 32 ? x : Arrays.copyOfRange(x, 1, 33);
	}

	public BigInteger modN(BigInteger x) {
		return x.mod(N);
	}

	public byte[] randomBytes() {
		return Random.generateRandomBytes(N);
	}

	public BigInteger randomNumber() {
		return Random.generateRandomNumber(N);
	}

	private static final BigInteger TWO = BigInteger.valueOf(2);
	private Map<Integer, BigInteger> pow2Cache = new HashMap<Integer, BigInteger>();
	private Map<Integer, BigInteger> pow2ModNCache = new HashMap<Integer, BigInteger>();

	public BigInteger pow2(int x) {
		if (pow2Cache.containsKey(x)) {
			return pow2Cache.get(x);
		}
		BigInteger ret = TWO.pow(x);
		pow2Cache.put(x, ret);
		return ret;
	}

	public BigInteger pow2ModN(int x) {
		if (pow2ModNCache.containsKey(x)) {
			return pow2ModNCache.get(x);
		}
		BigInteger ret = pow2(x).mod(N);
		pow2ModNCache.put(x, ret);
		return ret;
	}
}
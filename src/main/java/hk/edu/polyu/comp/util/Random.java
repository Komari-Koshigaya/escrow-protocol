package hk.edu.polyu.comp.util;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Random {

	public static SecureRandom getRandomGenerator(byte[] seed) {
		SecureRandom random = null;
		try {
			random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			if (seed != null && seed.length > 0) {
				random.setSeed(seed);
			}
			return random;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		return new SecureRandom();
	}

	public static byte[] generateRandomBytes(BigInteger max) {
		SecureRandom randomGen = getRandomGenerator(null);
		byte[] randomBytes = new byte[32];
		BigInteger randomCheck = null;
		do {
			randomGen.nextBytes(randomBytes);
			randomCheck = new BigInteger(1, randomBytes);
		} while (randomCheck.compareTo(BigInteger.ZERO) == 0 || randomCheck.compareTo(max) >= 0);
		return randomBytes;
	}

	public static BigInteger generateRandomNumber(BigInteger max) {
		return new BigInteger(1, generateRandomBytes(max));
	}
}

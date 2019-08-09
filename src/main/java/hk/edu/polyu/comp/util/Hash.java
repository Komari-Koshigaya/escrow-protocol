package hk.edu.polyu.comp.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {

	public static final MessageDigest SHA1;
	public static final MessageDigest SHA256;

	static {
		MessageDigest sha256 = null;
		MessageDigest sha1 = null;
		try {
			sha1 = MessageDigest.getInstance("SHA-1");
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		SHA1 = sha1;
		SHA256 = sha256;
	}

	public static byte[] sha1(byte[] value) {
		SHA1.reset();
		SHA1.update(value);
		return SHA1.digest();
	}

	public static byte[] sha256(byte[] value) {
		SHA256.reset();
		SHA256.update(value);
		return SHA256.digest();
	}

}

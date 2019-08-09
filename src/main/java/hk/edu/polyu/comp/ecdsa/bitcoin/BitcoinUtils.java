package hk.edu.polyu.comp.ecdsa.bitcoin;

import java.math.BigInteger;

import hk.edu.polyu.comp.DebugUtils;
import hk.edu.polyu.comp.util.BinaryUtils;

public class BitcoinUtils {
	public static final int VERSION_MAINNET = 0x80;
	public static final int VERSION_TESTNET = 0xef;
	
	public static final int KEY_LENGTH = 32;

	public static String encodePrivateKey(BigInteger privateKey, int version) {
		byte[] sk = privateKey.toByteArray();
		byte[] payload = BinaryUtils.fixLength(sk, KEY_LENGTH);
		return BitcoinBase58.encodeChecked(version, payload);
	}
}

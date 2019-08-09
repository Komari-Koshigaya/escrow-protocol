package hk.edu.polyu.comp.util;

import java.math.BigInteger;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class BinaryUtils {
	public static String encodeBinary(byte[] data) {
		String ret = new BigInteger(1, data).toString(2);
		int len = data.length * 8;
		ret = fixLength(ret, len);
		return ret;
	}

	public static String encodeBinary(byte[] data, int len) {
		String ret = encodeBinary(data);
		return fixLength(ret, len);
	}

	public static String encodeHex(byte[] data) {
		return new String(Hex.encodeHex(data)).toUpperCase();
	}

	public static String encodeHex(byte[] data, int len) {
		String ret = encodeHex(data);
		return fixLength(ret, len);
	}

	public static byte[] decodeHex(String data) throws DecoderException {
		return Hex.decodeHex(data.toCharArray());
	}

	public static String padZero(String data, int count) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < count; i++) {
			sb.append("0");
		}
		sb.append(data);
		return sb.toString();
	}

	public static String fixLength(String data, int len) {
		String ret = data;
		int diff = ret.length() - len;

		if (diff < 0) {
			ret = padZero(ret, -diff);
		} else if (diff > 0) {
			ret = ret.substring(diff, ret.length());
		}

		return ret;
	}
	
	public static byte[] fixLength(byte[] data, int len) {
		byte[] ret = new byte[len];
		int diff = data.length - len;

		if (diff < 0) {
			System.arraycopy(data, 0, ret, -diff, data.length);
		} else if (diff > 0) {
			System.arraycopy(data, diff, ret, 0, len);
		} else {
			return data;
		}

		return ret;
	}
}

package hk.edu.polyu.comp;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;

public class DebugUtils {

	public static void print(String x) {
		print("String", x);
	}

	public static void print(String msg, String x) {
		System.out.println(msg + ": " + x);
	}

	public static void print(byte[] x) {
		print("byte[]", x);
	}

	public static void print(String msg, byte[] x) {
		String hex = "";
		for (int i = 0; i < x.length; i++)
			hex += Integer.toString((x[i] & 0xff) + 0x100, 16).substring(1).toUpperCase();

		print(msg, hex);
	}

	public static void print(int x) {
		print("String", x);
	}

	public static void print(String msg, int x) {
		System.out.println(msg + ": " + x);
	}

	public static void print(BigInteger x) {
		print("BigInteger", x);
	}

	public static void print(String msg, BigInteger x) {
		print(msg, x.toString());
	}

	public static void print(BigDecimal x) {
		print("BigDecimal x", x);
	}

	public static void print(String msg, BigDecimal x) {
		print(msg, x.toString());
	}

	public static void print(ECPoint x) {
		print("ECPoint", x);
	}

	public static void print(String msg, ECPoint x) {
		// print(msg, x.toString());
		print(msg, x.getEncoded(true));
	}

	public static void printBigIntegerList(List<BigInteger> list) {
		System.out.println("List<BigInteger>");
		for (BigInteger item : list) {
			print(item);
		}
	}

	public static void printStringList(List<String> list) {
		System.out.println("List<String>");
		for (String item : list) {
			print(item);
		}
	}

	static Map<String, Long> timer = new HashMap<String, Long>();
	public static void timerStart(String timerName) {
		timer.put(timerName, System.nanoTime());
	}
	
	public static double timerEnd(String timerName) {
		double t = timer.get(timerName);
		t = System.nanoTime() - t;
		t /= 1000000;
		System.out.println(timerName + " used " + t + "ms");
		return t;
	}
}

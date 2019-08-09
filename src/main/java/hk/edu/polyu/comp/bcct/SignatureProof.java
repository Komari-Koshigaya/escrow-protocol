package hk.edu.polyu.comp.bcct;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class SignatureProof {

	EncryptedSignature signature;

	String x;
	BigInteger z1;
	BigInteger z2;
	List<BigInteger> zi1List;
	List<BigInteger> zi2List;
	List<BigInteger> zi3List;

	public SignatureProof() {
		super();
		zi1List = new ArrayList<BigInteger>();
		zi2List = new ArrayList<BigInteger>();
		zi3List = new ArrayList<BigInteger>();
	}
}

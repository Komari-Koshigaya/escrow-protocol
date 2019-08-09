package hk.edu.polyu.comp.bcct;

import java.util.List;

import org.bouncycastle.math.ec.ECPoint;

public class EncryptedSignature {

	public final List<ECBitCypher> cyphers;
	public final ECPoint R;

	public EncryptedSignature(List<ECBitCypher> cyphers, ECPoint r) {
		super();
		this.cyphers = cyphers;
		R = r;
	}
}

package hk.edu.polyu.comp.ecdsa;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public abstract class ECProtocal extends ECHelper {

	public final ECPoint G1;
	public final ECPoint G2;

	public ECProtocal(ECDomainParameters ec, ECPoint g1, ECPoint g2) {
		super(ec);
		G1 = g1;
		G2 = g2;
	}
}

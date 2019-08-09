package hk.edu.polyu.comp.bcct;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class ECBitCypher {

	public ECPoint u;
	public ECPoint v;

	public ECBitCypher() {
	}

	public ECBitCypher(ECBitCypher c) {
		this.u = c.u;
		this.v = c.v;
	}

	public ECBitCypher(ECPoint u, ECPoint v) {
		super();
		this.u = u;
		this.v = v;
	}

	public ECBitCypher add(ECBitCypher c) {
		ECBitCypher ret = new ECBitCypher(this);
		ret.u = ret.u.add(c.u);
		ret.v = ret.v.add(c.v);
		return ret;
	}

	public ECBitCypher subtract(ECBitCypher c) {
		ECBitCypher ret = new ECBitCypher(this);
		ret.u = ret.u.subtract(c.u);
		ret.v = ret.v.subtract(c.v);
		return ret;
	}

	public ECBitCypher multiply(BigInteger k) {
		ECBitCypher ret = new ECBitCypher(this);
		ret.u = ret.u.multiply(k);
		ret.v = ret.v.multiply(k);
		return ret;
	}

}

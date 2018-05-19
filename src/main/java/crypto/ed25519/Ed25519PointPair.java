package crypto.ed25519;

import crypto.Scalar;
import utils.ArrayUtils;
import utils.HexEncoder;

public class Ed25519PointPair {
    public Ed25519Point P1;
    public Ed25519Point P2;

    public Ed25519PointPair(Ed25519Point P1, Ed25519Point P2) {
        this.P1 = P1;
        this.P2 = P2;
    }

    public byte[] toBytes() {
        return ArrayUtils.concat(P1.toBytes(), P2.toBytes());
    }

    public Ed25519PointPair add(Ed25519PointPair a) {
        return new Ed25519PointPair(P1.add(a.P1), P2.add(a.P2));
    }

    public Ed25519PointPair subtract(Ed25519PointPair a) {
        return new Ed25519PointPair(P1.sub(a.P1), P2.sub(a.P2));
    }

    public Ed25519PointPair multiply(Scalar n) {
        return new Ed25519PointPair(P1.scalarMultiply(n), P2.scalarMultiply(n));
    }

    public boolean equals(Ed25519PointPair obj) {
        return P1.equals(obj.P1) && P2.equals(obj.P2);
    }

    @Override
    public String toString() {
        return "(P1: " + HexEncoder.getString(P1.toBytes()) + ", P2: " + P2 + ")";
    }

}

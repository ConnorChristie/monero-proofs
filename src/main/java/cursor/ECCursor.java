package cursor;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;
import crypto.ed25519.Ed25519PointPair;

public class ECCursor extends Cursor {
    public byte[] data;

    public ECCursor(byte[] data) {
        super(data);
    }

    public Ed25519Point readGroupElement() {
        return new Ed25519Point(readBytes(33));
    }

    public Ed25519PointPair[] readPointPairArray(int len) {
        Ed25519PointPair[] result = new Ed25519PointPair[len];
        for (int i = 0; i < len; i++) result[i] = new Ed25519PointPair(readGroupElement(), readGroupElement());
        return result;
    }

    public Scalar[][] readScalar2DArray(int m, int n) {
        Scalar[][] result = new Scalar[m][n];
        for (int j = 0; j < m; j++) {
            for (int i = 0; i < n; i++) {
                result[j][i] = readScalar();
            }
        }
        return result;
    }

}

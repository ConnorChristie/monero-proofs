package ringct.proofs;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;
import crypto.ed25519.Ed25519PointPair;
import utils.HexEncoder;

import java.math.BigInteger;

import static crypto.CryptoUtil.*;
import static crypto.Scalar.bigIntegerArrayToScalarArray;
import static crypto.Scalar.randomScalar;
import static utils.ArrayUtils.concat;

public class Proof2 {
    public Proof1 P;
    public Ed25519Point B; // cc
    public Ed25519PointPair[] G; // ss
    public Scalar z;

    public Proof2(Proof1 P, Ed25519Point B, Ed25519PointPair[] G, Scalar z) {
        this.P = P;
        this.B = B;
        this.G = G;
        this.z = z;
    }

    public static Proof2 prove(Ed25519PointPair[] co, int iAsterisk, Scalar r, int decompositionBase, int decompositionExponent) {
        int ringSize = (int) Math.pow(decompositionBase, decompositionExponent);

        Scalar[] u = new Scalar[decompositionExponent];
        for (int k = 0; k < decompositionExponent; k++) u[k] = randomScalar();

        Scalar rB = randomScalar();

        int[] iAsteriskSequence = nAryDecompose(decompositionBase, iAsterisk, decompositionExponent);

        Scalar[][] d = new Scalar[decompositionExponent][decompositionBase];
        for (int j = 0; j < decompositionExponent; j++) {
            for (int i = 0; i < decompositionBase; i++) {
                d[j][i] = Scalar.intToScalar(delta(iAsteriskSequence[j], i));
            }
        }

        Ed25519Point B = COMb(d, rB);

        Proof1 P = Proof1.prove(d, rB);

        Scalar[][] coefs = COEFS(P.a, iAsterisk);

        Ed25519PointPair[] G = new Ed25519PointPair[decompositionExponent];

        for (int k = 0; k < decompositionExponent; k++) {
            G[k] = ENCeg(Ed25519Point.ZERO, u[k]);
            for (int i = 0; i < ringSize; i++) {
                G[k] = G[k].add(co[i].multiply(coefs[i][k]));
            }
        }

        byte[] bytes = concat(P.A.toBytes(), P.C.toBytes(), P.D.toBytes());
        Scalar x1 = hashToScalar(bytes);

        Scalar z = r.mul(x1.pow(decompositionExponent));
        for (int i = decompositionExponent - 1; i >= 0; i--) {
            z = z.sub(u[i].mul(x1.pow(i)));
        }
        return new Proof2(P, B, G, z);
    }

    public boolean isValid(int decompositionBase, Ed25519PointPair[] co) {

        boolean abcdOnCurve =
                P.A.satisfiesCurveEquation()
                        && B.satisfiesCurveEquation()
                        && P.C.satisfiesCurveEquation()
                        && P.D.satisfiesCurveEquation();
        if (!abcdOnCurve) {
            System.out.println("VALID2: FAILED: ABCD not on curve");
            return false;
        }

        if (!P.isValid(B)) {
            System.out.println("VALID2: FAILED: VALID1 failed");
            return false;
        }

        Scalar x1 = hashToScalar(concat(P.A.toBytes(), P.C.toBytes(), P.D.toBytes()));

        int decompositionExponent = P.fTrimmed.length;
        Scalar[][] f = new Scalar[decompositionExponent][decompositionBase];
        for (int j = 0; j < decompositionExponent; j++) {
            System.arraycopy(P.fTrimmed[j], 0, f[j], 1, decompositionBase - 1);
        }

        int ringSize = (int) Math.pow(decompositionBase, decompositionExponent);

        Ed25519PointPair c = ENCeg(Ed25519Point.ZERO, z);

        Scalar x = hashToScalar(concat(P.A.toBytes(), P.C.toBytes(), P.D.toBytes()));
        for (int j = 0; j < decompositionExponent; j++) {
            f[j][0] = x;
            for (int i = 1; i < decompositionBase; i++) {
                f[j][0] = f[j][0].sub(f[j][i]);
            }
        }

        Scalar[] g = new Scalar[ringSize];
        g[0] = f[0][0];
        for (int j = 1; j < decompositionExponent; j++) {
            g[0] = g[0].mul(f[j][0]);
        }

        Ed25519PointPair c1 = co[0].multiply(g[0]);
        for (int i = 1; i < ringSize; i++) {
            int[] iSequence = nAryDecompose(decompositionBase, i, decompositionExponent);
            g[i] = f[0][iSequence[0]];
            for (int j = 1; j < decompositionExponent; j++) {
                g[i] = g[i].mul(f[j][iSequence[j]]);
            }
            c1 = c1.add(co[i].multiply(g[i]));
        }

        for (int k = 0; k < decompositionExponent; k++) {
            c1 = c1.subtract(G[k].multiply(x1.pow(k)));
        }


        boolean result = c1.equals(c);
        if (!result) {
            System.out.println("VALID2: FAILED: c' != c");
            System.out.println("c:  (" + HexEncoder.getString(c.P1.toBytes()) + ", " + HexEncoder.getString(c
                    .P2.toBytes()));
            System.out.println("c': (" + HexEncoder.getString(c1.P1.toBytes()) + ", " + HexEncoder.getString
                    (c1.P2.toBytes()));
        }
        return result;

    }

    public byte[] toBytes(int decompositionBase, int decompositionExponent) {
        byte[] bytes;
        bytes = concat(P.toBytes(decompositionBase, decompositionExponent), B.toBytes());
        for (Ed25519PointPair g : G) bytes = concat(bytes, g.toBytes());
        bytes = concat(bytes, z.bytes);
        return bytes;
    }

    public static Scalar[][] COEFS(Scalar[][] a, int iAsterisk) {
        int decompositionBase = a[0].length; // n
        int decompositionExponent = a.length; // m
        int ringSize = (int) Math.pow(decompositionBase, decompositionExponent); // N = n^m

        int[] iAsteriskSequence = nAryDecompose(decompositionBase, iAsterisk, decompositionExponent);

        Scalar[][] coefList = new Scalar[ringSize][decompositionExponent];

        for (int k = 0; k < ringSize; k++) {
            int[] kSequence = nAryDecompose(decompositionBase, k, decompositionExponent);
            coefList[k] = new Scalar[]{
                    a[0][kSequence[0]],
                    Scalar.intToScalar(delta(iAsteriskSequence[0], kSequence[0]))
            };

            for (int j = 1; j < decompositionExponent; j++) {
                coefList[k] = COEFPROD(coefList[k], new Scalar[]{
                        a[j][kSequence[j]],
                        Scalar.intToScalar(delta(iAsteriskSequence[j], kSequence[j]))
                });
            }
        }
        for (int k = 0; k < ringSize; k++) {
            coefList[k] = trimScalarArray(coefList[k], decompositionExponent, decompositionExponent);
        }
        return coefList;
    }

    public static Scalar[] COEFPROD(Scalar[] c, Scalar[] d) {
        int maxLen = Math.max(c.length, d.length);
        int resultLen = 2 * maxLen - 1;
        BigInteger[] result = new BigInteger[resultLen];

        for (int i = 0; i < resultLen; i++) result[i] = BigInteger.ZERO;
        for (int i = 0; i < maxLen; i++) {
            for (int j = 0; j < maxLen; j++) {
                result[i + j] = result[i + j].add(getBigIntegerAtArrayIndex(c, i).multiply(getBigIntegerAtArrayIndex
                        (d, j)));
            }
        }
        return bigIntegerArrayToScalarArray(result);
    }

    private static Scalar[] trimScalarArray(Scalar[] a, int len, int indexWhere1ValueCanBeTrimmed) {
        Scalar[] r = new Scalar[len];
        for (int i = 0; i < a.length; i++) {
            if (i < len) r[i] = a[i];
            else {
                if (i == indexWhere1ValueCanBeTrimmed) {
                    if (!(a[i].equals(Scalar.ZERO) || a[i].equals(Scalar.ONE)))
                        throw new RuntimeException("Attempt to trim non-zero or non-one in column " + i + ": value: "
                                + a[i].toBigInteger());
                } else {
                    if (!(a[i].equals(Scalar.ZERO)))
                        throw new RuntimeException("Attempt to trim non-zero in column " + i + ": value: " + a[i]
                                .toBigInteger());
                }
            }
        }
        return r;
    }

    private static BigInteger getBigIntegerAtArrayIndex(Scalar[] a, int index) {
        if (index >= a.length) return BigInteger.ZERO;
        else return a[index].toBigInteger();
    }

    private static int intPow(int a, int b) {
        return (int) Math.round(Math.pow(a, b));
    }

    private static int delta(int j, int i) {
        return j == i ? 1 : 0;
    }

    public static int[] nAryDecompose(int base, int n, int decompositionExponent) {
        int[] r = new int[decompositionExponent];
        for (int i = decompositionExponent - 1; i >= 0; i--) {
            int basePow = intPow(base, i);
            r[i] = n / basePow;
            n -= basePow * r[i];
        }
        return r;
    }

}

package ringct.proofs;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;

import static crypto.CryptoUtil.COMb;
import static crypto.CryptoUtil.hashToScalar;
import static crypto.Scalar.randomScalar;
import static utils.ArrayUtils.concat;

public class Proof1 {
    public Ed25519Point A;
    public Ed25519Point C;
    public Ed25519Point D;
    public Scalar[][] fTrimmed;
    private Scalar zA;
    private Scalar zC;
    public transient Scalar[][] a;

    public Proof1(Ed25519Point A, Ed25519Point C, Ed25519Point D, Scalar[][] fTrimmed,
                  Scalar zA, Scalar zC, Scalar[][] a) {
        this.A = A;
        this.C = C;
        this.D = D;
        this.fTrimmed = fTrimmed;
        this.zA = zA;
        this.zC = zC;
        this.a = a;
    }

    public static Proof1 prove(Scalar[][] b, Scalar r) {
        int decompositionExponent = b.length;
        int decompositionBase = b[0].length;

        Scalar rA = randomScalar();
        Scalar rC = randomScalar();
        Scalar rD = randomScalar();

        Scalar[][] a = new Scalar[decompositionExponent][decompositionBase];
        for (int j = 0; j < decompositionExponent; j++) {
            for (int i = 1; i < decompositionBase; i++) {
                a[j][i] = randomScalar();
            }
        }

        for (int j = 0; j < decompositionExponent; j++) {
            a[j][0] = Scalar.ZERO;
            for (int i = 1; i < decompositionBase; i++) {
                a[j][0] = a[j][0].sub(a[j][i]);
            }
        }

        Ed25519Point A = COMb(a, rA);

        Scalar[][] c = new Scalar[decompositionExponent][decompositionBase];
        Scalar[][] d = new Scalar[decompositionExponent][decompositionBase];
        for (int j = 0; j < decompositionExponent; j++) {
            for (int i = 0; i < decompositionBase; i++) {
                c[j][i] = a[j][i].mul(Scalar.ONE.sub(b[j][i].mul(Scalar.TWO)));
                d[j][i] = a[j][i].sq().mul(Scalar.MINUS_ONE);
            }
        }

        Ed25519Point C = COMb(c, rC);
        Ed25519Point D = COMb(d, rD);

        Scalar x = hashToScalar(concat(A.toBytes(), C.toBytes(), D.toBytes()));

        Scalar[][] f = new Scalar[decompositionExponent][decompositionBase];
        for (int j = 0; j < decompositionExponent; j++) {
            for (int i = 0; i < decompositionBase; i++) {
                f[j][i] = b[j][i].mul(x).add(a[j][i]);
            }
        }

        Scalar[][] fTrimmed = new Scalar[decompositionExponent][decompositionBase - 1];
        for (int j = 0; j < decompositionExponent; j++) {
            System.arraycopy(f[j], 1, fTrimmed[j], 0, decompositionBase - 1);
        }

        Scalar zA = r.mul(x).add(rA);
        Scalar zC = rC.mul(x).add(rD);

        return new Proof1(A, C, D, fTrimmed, zA, zC, a);
    }

    public boolean isValid(Ed25519Point B) {
        boolean abcdOnCurve =
                A.satisfiesCurveEquation()
                        && B.satisfiesCurveEquation()
                        && C.satisfiesCurveEquation()
                        && D.satisfiesCurveEquation();

        if (!abcdOnCurve) {
            System.out.println("VALID1: ABCD not on curve");
            return false;
        }

        int decompositionExponent = fTrimmed.length;
        int decompositionBase = fTrimmed[0].length + 1;

        Scalar[][] f = new Scalar[decompositionExponent][decompositionBase];
        for (int j = 0; j < decompositionExponent; j++) {
            System.arraycopy(fTrimmed[j], 0, f[j], 1, decompositionBase - 1);
        }

        Scalar x = hashToScalar(concat(A.toBytes(), C.toBytes(), D.toBytes()));

        for (int j = 0; j < decompositionExponent; j++) {
            f[j][0] = x;
            for (int i = 1; i < decompositionBase; i++) {
                f[j][0] = f[j][0].sub(f[j][i]);
            }
        }

        Scalar[][] f1 = new Scalar[decompositionExponent][decompositionBase];
        for (int j = 0; j < decompositionExponent; j++) {
            for (int i = 0; i < decompositionBase; i++) {
                f1[j][i] = f[j][i].mul(x.sub(f[j][i]));
            }
        }

        for (int j = 0; j < decompositionExponent; j++) {
            Scalar colSum = x;
            for (int i = 1; i < decompositionBase; i++) {
                colSum = colSum.sub(f[j][i]);
            }
            if (!f[j][0].equals(colSum)) {
                System.out.println("VALID1: FAILED For each j=0, ..., m-1, f[j][0] == x-f[j][1]-f[j][2]- ... " +
                        "-f[j][n-1]");
                return false;
            }
        }

        if (!B.scalarMultiply(x).add(A).equals(COMb(f, zA))) {
            System.out.println("VALID1: FAILED xB + A == COMp(f[0][0], ..., f[m-1][n-1]; z[A])");
            return false;
        }
        if (!C.scalarMultiply(x).add(D).equals(COMb(f1, zC))) {
            System.out.println("VALID1: FAILED xC + D == COMp(f'[0][0], ..., f'[m-1][n-1]; z[C])");
            return false;
        }

        return true;

    }

    public byte[] toBytes(int decompositionBase, int decompositionExponent) {
        byte[] result = concat(A.toBytes(), C.toBytes(), D.toBytes());
        for (int j = 0; j < decompositionExponent; j++) {
            for (int i = 0; i < decompositionBase - 1; i++) {
                result = concat(result, fTrimmed[j][i].bytes);
            }
        }
        result = concat(result, zA.bytes, zC.bytes);
        return result;
    }
}

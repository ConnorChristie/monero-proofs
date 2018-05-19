package ringct.proofs;

import crypto.CryptoUtil;
import crypto.Scalar;
import crypto.ed25519.Ed25519Point;

import java.math.BigInteger;

import static crypto.CryptoUtil.getHpnGLookup;
import static crypto.CryptoUtil.hashToScalar;
import static crypto.Scalar.randomScalar;
import static utils.ArrayUtils.concat;

public class BulletProof {
    public Ed25519Point V;
    public Ed25519Point A;
    public Ed25519Point S;
    public Ed25519Point T1;
    public Ed25519Point T2;
    public Scalar taux;
    public Scalar mu;
    public Ed25519Point[] L;
    public Ed25519Point[] R;
    public Scalar a;
    public Scalar b;
    public Scalar t;

    private final static int N = 64;
    private final static int logN = 6;

    private static Ed25519Point G;
    private static Ed25519Point H;
    private static Ed25519Point[] Gi;
    private static Ed25519Point[] Hi;

    static {
        // Set the curve base points
        G = Ed25519Point.G;
        H = Ed25519Point.hashToPoint(G);

        Gi = new Ed25519Point[N];
        Hi = new Ed25519Point[N];

        for (int i = 0; i < N; i++) {
            Gi[i] = getHpnGLookup(2 * i);
            Hi[i] = getHpnGLookup(2 * i + 1);
        }
    }

    public BulletProof(Ed25519Point V, Ed25519Point A, Ed25519Point S, Ed25519Point T1, Ed25519Point T2, Scalar
            taux, Scalar mu, Ed25519Point[] L, Ed25519Point[] R, Scalar a, Scalar b, Scalar t) {
        this.V = V;
        this.A = A;
        this.S = S;
        this.T1 = T1;
        this.T2 = T2;
        this.taux = taux;
        this.mu = mu;
        this.L = L;
        this.R = R;
        this.a = a;
        this.b = b;
        this.t = t;
    }

    public byte[] toBytes() {
        byte[] result;
        result = concat(V.toBytes(), A.toBytes(), S.toBytes(), T1.toBytes(), T2.toBytes(), taux.bytes, mu.bytes);
        for (Ed25519Point l : L)
            result = concat(result, l.toBytes());
        for (Ed25519Point r : R)
            result = concat(result, r.toBytes());
        result = concat(result, a.bytes, b.bytes, t.bytes);
        return result;
    }

    /* Given a value v (0..2^N-1) and a mask gamma, construct a range proof */
    public static BulletProof prove(Scalar value, Scalar gamma) {
        Ed25519Point V = H.scalarMultiply(value).add(G.scalarMultiply(gamma));

        // This hash is updated for Fiat-Shamir throughout the proof
        Scalar hashCache = hashToScalar(V.toBytes());

        // PAPER LINES 36-37
        Scalar[] aL = new Scalar[N];
        Scalar[] aR = new Scalar[N];

        BigInteger tempV = value.toBigInteger();
        for (int i = N - 1; i >= 0; i--) {
            BigInteger basePow = BigInteger.valueOf(2).pow(i);
            if (tempV.divide(basePow).equals(BigInteger.ZERO)) {
                aL[i] = Scalar.ZERO;
            } else {
                aL[i] = Scalar.ONE;
                tempV = tempV.subtract(basePow);
            }

            aR[i] = aL[i].sub(Scalar.ONE);
        }

        // PAPER LINES 38-39
        Scalar alpha = randomScalar();
        Ed25519Point A = vectorExponent(aL, aR).add(G.scalarMultiply(alpha));

        // PAPER LINES 40-42
        Scalar[] sL = new Scalar[N];
        Scalar[] sR = new Scalar[N];
        for (int i = 0; i < N; i++) {
            sL[i] = randomScalar();
            sR[i] = randomScalar();
        }
        Scalar rho = randomScalar();
        Ed25519Point S = vectorExponent(sL, sR).add(G.scalarMultiply(rho));

        // PAPER LINES 43-45
        hashCache = hashToScalar(concat(hashCache.bytes, A.toBytes()));
        hashCache = hashToScalar(concat(hashCache.bytes, S.toBytes()));
        Scalar y = hashCache;
        hashCache = hashToScalar(hashCache.bytes);
        Scalar z = hashCache;

        // Polynomial construction before PAPER LINE 46
        Scalar t1 = Scalar.ZERO;
        Scalar t2 = Scalar.ZERO;

        t1 = t1.add(innerProduct(vectorSubtract(aL, vectorScalar(vectorPowers(Scalar.ONE), z)), hadamard(vectorPowers
                (y), sR)));
        t1 = t1.add(innerProduct(sL, vectorAdd(hadamard(vectorPowers(y), vectorAdd(aR, vectorScalar(vectorPowers
                (Scalar.ONE), z))), vectorScalar(vectorPowers(Scalar.TWO), z.sq()))));

        t2 = t2.add(innerProduct(sL, hadamard(vectorPowers(y), sR)));

        // PAPER LINES 47-48
        Scalar tau1 = randomScalar();
        Scalar tau2 = randomScalar();
        Ed25519Point T1 = H.scalarMultiply(t1).add(G.scalarMultiply(tau1));
        Ed25519Point T2 = H.scalarMultiply(t2).add(G.scalarMultiply(tau2));

        // PAPER LINES 49-51
        hashCache = hashToScalar(concat(hashCache.bytes, z.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, T1.toBytes()));
        hashCache = hashToScalar(concat(hashCache.bytes, T2.toBytes()));
        Scalar x = hashCache;

        // PAPER LINES 52-53
        Scalar taux = tau1.mul(x);
        taux = taux.add(tau2.mul(x.sq()));
        taux = taux.add(gamma.mul(z.sq()));
        Scalar mu = x.mul(rho).add(alpha);

        // PAPER LINES 54-57
        Scalar[] l = vectorAdd(vectorSubtract(aL, vectorScalar(vectorPowers(Scalar.ONE), z)), vectorScalar(sL, x));
        Scalar[] r = vectorAdd(hadamard(vectorPowers(y), vectorAdd(aR, vectorAdd(vectorScalar(vectorPowers(Scalar
                .ONE), z), vectorScalar(sR, x)))), vectorScalar(vectorPowers(Scalar.TWO), z.sq()));

        Scalar t = innerProduct(l, r);

        // PAPER LINES 32-33
        hashCache = hashToScalar(concat(hashCache.bytes, x.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, taux.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, mu.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, t.bytes));
        Scalar x_ip = hashCache;

        // These are used in the inner product rounds
        int nPrime = N;
        Ed25519Point[] GPrime = new Ed25519Point[N];
        Ed25519Point[] HPrime = new Ed25519Point[N];
        Scalar[] aPrime = new Scalar[N];
        Scalar[] bPrime = new Scalar[N];
        for (int i = 0; i < N; i++) {
            GPrime[i] = Gi[i];
            HPrime[i] = Hi[i].scalarMultiply(invert(y).pow(i));
            aPrime[i] = l[i];
            bPrime[i] = r[i];
        }
        Ed25519Point[] L = new Ed25519Point[logN];
        Ed25519Point[] R = new Ed25519Point[logN];
        int round = 0; // track the index based on number of rounds
        Scalar[] w = new Scalar[logN]; // this is the challenge x in the inner product protocol

        // PAPER LINE 13
        while (nPrime > 1) {
            // PAPER LINE 15
            nPrime /= 2;

            // PAPER LINES 16-17
            Scalar cL = innerProduct(scalarSlice(aPrime, 0, nPrime), scalarSlice(bPrime, nPrime, bPrime.length));
            Scalar cR = innerProduct(scalarSlice(aPrime, nPrime, aPrime.length), scalarSlice(bPrime, 0, nPrime));

            // PAPER LINES 18-19
            L[round] = vectorExponentCustom(curveSlice(GPrime, nPrime, GPrime.length), curveSlice(HPrime, 0, nPrime),
                    scalarSlice(aPrime, 0, nPrime), scalarSlice(bPrime, nPrime, bPrime.length)).add(H.scalarMultiply
                    (cL.mul(x_ip)));
            R[round] = vectorExponentCustom(curveSlice(GPrime, 0, nPrime), curveSlice(HPrime, nPrime, HPrime.length),
                    scalarSlice(aPrime, nPrime, aPrime.length), scalarSlice(bPrime, 0, nPrime)).add(H.scalarMultiply
                    (cR.mul(x_ip)));

            // PAPER LINES 21-22
            hashCache = hashToScalar(concat(hashCache.bytes, L[round].toBytes()));
            hashCache = hashToScalar(concat(hashCache.bytes, R[round].toBytes()));
            w[round] = hashCache;

            // PAPER LINES 24-25
            GPrime = hadamard2(vectorScalar2(curveSlice(GPrime, 0, nPrime), invert(w[round])), vectorScalar2
                    (curveSlice(GPrime, nPrime, GPrime.length), w[round]));
            HPrime = hadamard2(vectorScalar2(curveSlice(HPrime, 0, nPrime), w[round]), vectorScalar2(curveSlice
                    (HPrime, nPrime, HPrime.length), invert(w[round])));

            // PAPER LINES 28-29
            aPrime = vectorAdd(vectorScalar(scalarSlice(aPrime, 0, nPrime), w[round]), vectorScalar(scalarSlice
                    (aPrime, nPrime, aPrime.length), invert(w[round])));
            bPrime = vectorAdd(vectorScalar(scalarSlice(bPrime, 0, nPrime), invert(w[round])), vectorScalar
                    (scalarSlice(bPrime, nPrime, bPrime.length), w[round]));

            round += 1;
        }

        // PAPER LINE 58 (with inclusions from PAPER LINE 8 and PAPER LINE 20)
        return new BulletProof(V, A, S, T1, T2, taux, mu, L, R, aPrime[0], bPrime[0], t);
    }

    /* Given a range proof, determine if it is valid */
    public boolean verify() {
        // Reconstruct the challenges
        Scalar hashCache = hashToScalar(V.toBytes());
        hashCache = hashToScalar(concat(hashCache.bytes, A.toBytes()));
        hashCache = hashToScalar(concat(hashCache.bytes, S.toBytes()));
        Scalar y = hashCache;
        hashCache = hashToScalar(hashCache.bytes);
        Scalar z = hashCache;
        hashCache = hashToScalar(concat(hashCache.bytes, z.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, T1.toBytes()));
        hashCache = hashToScalar(concat(hashCache.bytes, T2.toBytes()));
        Scalar x = hashCache;
        hashCache = hashToScalar(concat(hashCache.bytes, x.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, taux.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, mu.bytes));
        hashCache = hashToScalar(concat(hashCache.bytes, t.bytes));
        Scalar x_ip = hashCache;

        // PAPER LINE 61
        Ed25519Point L61Left = G.scalarMultiply(taux).add(H.scalarMultiply(t));

        Scalar k = computeK(y, z);

        Ed25519Point L61Right = H.scalarMultiply(k.add(z.mul(innerProduct(vectorPowers(Scalar.ONE), vectorPowers(y)))));
        L61Right = L61Right.add(V.scalarMultiply(z.sq()));
        L61Right = L61Right.add(T1.scalarMultiply(x));
        L61Right = L61Right.add(T2.scalarMultiply(x.sq()));

        if (!L61Right.equals(L61Left))
            return false;

        // PAPER LINE 62
        Ed25519Point P = Ed25519Point.ZERO;
        P = P.add(A);
        P = P.add(S.scalarMultiply(x));

        // Compute the number of rounds for the inner product
        int rounds = L.length;

        // PAPER LINES 21-22
        // The inner product challenges are computed per round
        Scalar[] w = new Scalar[rounds];
        hashCache = hashToScalar(concat(hashCache.bytes, L[0].toBytes()));
        hashCache = hashToScalar(concat(hashCache.bytes, R[0].toBytes()));
        w[0] = hashCache;
        if (rounds > 1) {
            for (int i = 1; i < rounds; i++) {
                hashCache = hashToScalar(concat(hashCache.bytes, L[i].toBytes()));
                hashCache = hashToScalar(concat(hashCache.bytes, R[i].toBytes()));
                w[i] = hashCache;
            }
        }

        // Basically PAPER LINES 24-25
        // Compute the curvepoints from G[i] and H[i]
        Ed25519Point InnerProdG = Ed25519Point.ZERO;
        Ed25519Point InnerProdH = Ed25519Point.ZERO;
        for (int i = 0; i < N; i++) {
            // Convert the index to binary IN REVERSE and construct the scalar exponent
            int index = i;
            Scalar gScalar = a;
            Scalar hScalar = b.mul(invert(y).pow(i));

            for (int j = rounds - 1; j >= 0; j--) {
                int J = w.length - j - 1; // because this is done in reverse bit order
                int basePow = (int) Math.pow(2, j); // assumes we don't get too big
                if (index / basePow == 0) // bit is zero
                {
                    gScalar = gScalar.mul(invert(w[J]));
                    hScalar = hScalar.mul(w[J]);
                } else // bit is one
                {
                    gScalar = gScalar.mul(w[J]);
                    hScalar = hScalar.mul(invert(w[J]));
                    index -= basePow;
                }
            }

            // Adjust the scalars using the exponents from PAPER LINE 62
            gScalar = gScalar.add(z);
            hScalar = hScalar.sub(z.mul(y.pow(i)).add(z.sq().mul(Scalar.TWO.pow(i))).mul(invert(y).pow(i)));

            // Now compute the basepoint's scalar multiplication
            // Each of these could be written as a multiexp operation instead
            InnerProdG = InnerProdG.add(Gi[i].scalarMultiply(gScalar));
            InnerProdH = InnerProdH.add(Hi[i].scalarMultiply(hScalar));
        }

        // PAPER LINE 26
        Ed25519Point PPrime = P.add(G.scalarMultiply(Scalar.ZERO.sub(mu)));

        for (int i = 0; i < rounds; i++) {
            PPrime = PPrime.add(L[i].scalarMultiply(w[i].sq()));
            PPrime = PPrime.add(R[i].scalarMultiply(invert(w[i]).sq()));
        }
        PPrime = PPrime.add(H.scalarMultiply(t.mul(x_ip)));

        return PPrime.equals(InnerProdG.add(InnerProdH).add(H.scalarMultiply(a.mul(b).mul(x_ip))));
    }

    /* Given two scalar arrays, construct a vector commitment */
    private static Ed25519Point vectorExponent(Scalar[] a, Scalar[] b) {
        assert a.length == N && b.length == N;

        Ed25519Point Result = Ed25519Point.ZERO;
        for (int i = 0; i < N; i++) {
            Result = Result.add(Gi[i].scalarMultiply(a[i]));
            Result = Result.add(Hi[i].scalarMultiply(b[i]));
        }
        return Result;
    }

    /* Compute a custom vector-scalar commitment */
    private static Ed25519Point vectorExponentCustom(Ed25519Point[] A, Ed25519Point[] B, Scalar[] a, Scalar[] b) {
        assert a.length == A.length && b.length == B.length && a.length == b.length;

        Ed25519Point Result = Ed25519Point.ZERO;
        for (int i = 0; i < a.length; i++) {
            Result = Result.add(A[i].scalarMultiply(a[i]));
            Result = Result.add(B[i].scalarMultiply(b[i]));
        }
        return Result;
    }

    /* Given a scalar, construct a vector of powers */
    private static Scalar[] vectorPowers(Scalar scalar) {
        Scalar[] result = new Scalar[N];
        for (int i = 0; i < N; i++) {
            result[i] = scalar.pow(i);
        }
        return result;
    }

    /* Given two scalar arrays, construct the inner product */
    private static Scalar innerProduct(Scalar[] a, Scalar[] b) {
        assert a.length == b.length;

        Scalar result = Scalar.ZERO;
        for (int i = 0; i < a.length; i++) {
            result = result.add(a[i].mul(b[i]));
        }
        return result;
    }

    /* Given two scalar arrays, construct the Hadamard product */
    private static Scalar[] hadamard(Scalar[] a, Scalar[] b) {
        assert a.length == b.length;

        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i].mul(b[i]);
        }
        return result;
    }

    /* Given two curvepoint arrays, construct the Hadamard product */
    private static Ed25519Point[] hadamard2(Ed25519Point[] A, Ed25519Point[] B) {
        assert A.length == B.length;

        Ed25519Point[] Result = new Ed25519Point[A.length];
        for (int i = 0; i < A.length; i++) {
            Result[i] = A[i].add(B[i]);
        }
        return Result;
    }

    /* Add two vectors */
    private static Scalar[] vectorAdd(Scalar[] a, Scalar[] b) {
        assert a.length == b.length;

        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i].add(b[i]);
        }
        return result;
    }

    /* Subtract two vectors */
    private static Scalar[] vectorSubtract(Scalar[] a, Scalar[] b) {
        assert a.length == b.length;

        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i].sub(b[i]);
        }
        return result;
    }

    /* Multiply a scalar and a vector */
    private static Scalar[] vectorScalar(Scalar[] a, Scalar scalar) {
        Scalar[] result = new Scalar[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i].mul(scalar);
        }
        return result;
    }

    /* Exponentiate a curve vector by a scalar */
    private static Ed25519Point[] vectorScalar2(Ed25519Point[] A, Scalar x) {
        Ed25519Point[] Result = new Ed25519Point[A.length];
        for (int i = 0; i < A.length; i++) {
            Result[i] = A[i].scalarMultiply(x);
        }
        return Result;
    }

    /* Compute the inverse of a scalar, the stupid way */
    private static Scalar invert(Scalar scalar) {
        Scalar inverse = new Scalar(scalar.toBigInteger().modInverse(CryptoUtil.l));

        assert scalar.mul(inverse).equals(Scalar.ONE);
        return inverse;
    }

    /* Compute the slice of a curvepoint vector */
    private static Ed25519Point[] curveSlice(Ed25519Point[] a, int start, int stop) {
        Ed25519Point[] Result = new Ed25519Point[stop - start];
        System.arraycopy(a, start, Result, 0, stop - start);
        return Result;
    }

    /* Compute the slice of a scalar vector */
    private static Scalar[] scalarSlice(Scalar[] a, int start, int stop) {
        Scalar[] result = new Scalar[stop - start];
        System.arraycopy(a, start, result, 0, stop - start);
        return result;
    }

    /* Compute the value of k(y,z) */
    private static Scalar computeK(Scalar y, Scalar z) {
        Scalar result = Scalar.ZERO;
        result = result.sub(z.sq().mul(innerProduct(vectorPowers(Scalar.ONE), vectorPowers(y))));
        result = result.sub(z.pow(3).mul(innerProduct(vectorPowers(Scalar.ONE), vectorPowers(Scalar.TWO))));

        return result;
    }
}

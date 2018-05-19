package crypto;

import crypto.ed25519.Ed25519Point;
import crypto.ed25519.Ed25519PointPair;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.bouncycastle.util.Arrays;
import utils.ArrayUtils;
import utils.ExceptionUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static utils.ArrayUtils.concat;

public class CryptoUtil {

    public static final Random random = new SecureRandom();
    public static GenericObjectPool<Keccak> keccakPool = new GenericObjectPool<>(new BasePooledObjectFactory<Keccak>() {

        @Override
        public PooledObject<Keccak> wrap(Keccak keccak) {
            return new DefaultPooledObject<>(keccak);
        }

        @Override
        public Keccak create() throws Exception {
            return new Keccak(256);
        }
    });
    public static BigInteger l = BigInteger.valueOf(2).pow(252).add(new BigInteger
            ("27742317777372353535851937790883648493"));
    public static Map<Integer, Ed25519Point> HpnGLookup = new HashMap<>();

    public static Scalar hashToScalar(byte[] a) {
        return new Scalar(scReduce32(fastHash(a)));
    }

    public static byte[] fastHash(byte[] a) {
        try {
            Keccak keccak = keccakPool.borrowObject();
            try {
                keccak.reset();
                keccak.update(a);
                return keccak.digestArray();
            } finally {
                keccakPool.returnObject(keccak);
            }
        } catch (Exception e) {
            throw ExceptionUtils.toRuntimeException(e);
        }
    }

    public static byte[] scReduce32(byte[] a) {
        byte[] r = getBigIntegerFromUnsignedLittleEndianByteArray(a).mod(l).toByteArray();
        return ensure32BytesAndConvertToLittleEndian(r);
    }

    public static byte[] ensure32BytesAndConvertToLittleEndian(byte[] r) {
        byte[] s = new byte[32];
        if (r.length > 32) System.arraycopy(r, 1, s, 0, s.length);
        else System.arraycopy(r, 0, s, 32 - r.length, r.length);
        return Arrays.reverse(s);
    }

    public static BigInteger getBigIntegerFromUnsignedLittleEndianByteArray(byte[] a1) {
        byte[] a = new byte[a1.length];
        System.arraycopy(a1, 0, a, 0, 32);
        byte[] a2 = new byte[33];
        System.arraycopy(Arrays.reverse(a), 0, a2, 1, 32);
        return new BigInteger(a2);
    }

    public static byte[] getUnsignedLittleEndianByteArrayFromBigInteger(BigInteger n) {
        byte[] a = n.toByteArray();
        byte[] a2 = new byte[32];
        System.arraycopy(a, 0, a2, 32 - a.length, a.length);
        return Arrays.reverse(a2);
    }

    public static byte[] randomMessage(int len) {
        byte[] m = new byte[len];
        random.nextBytes(m);
        return m;
    }

    public static byte[] toBytes(Ed25519Point[] a) {
        byte[] r = new byte[0];
        for (Ed25519Point ai : a) r = ArrayUtils.concat(r, ai.toBytes());
        return r;
    }

    public static Scalar sumArray(Scalar[] a) {
        Scalar r = Scalar.ZERO;
        for (Scalar ai : a) r = r.add(ai);
        return r;
    }

    public static Ed25519PointPair COMeg(Scalar xAmount, Scalar rMask) {
        return new Ed25519PointPair(Ed25519Point.G.scalarMultiply(xAmount).add(getHpnGLookup(1).scalarMultiply(rMask)
        ), Ed25519Point.G.scalarMultiply(rMask));
    }

    public static Ed25519Point COMp(Scalar xAmount, Scalar rMask) {
        return Ed25519Point.G.scalarMultiply(xAmount).add(getHpnGLookup(1).scalarMultiply(rMask));
    }

    public static Ed25519Point COMb(Scalar[][] x, Scalar r) {
        int m = x.length;
        int n = x[0].length;
        Ed25519Point A = Ed25519Point.G.scalarMultiply(r);
        for (int j = 0; j < m; j++) {
            for (int i = 0; i < n; i++) {
                A = A.add(getHpnGLookup(j * n + i + 1).scalarMultiply(x[j][i]));
            }
        }
        return A;
    }

    public static Ed25519Point getHpnGLookup(int n) {
        if (!HpnGLookup.containsKey(n)) {
            Ed25519Point HpnG = Ed25519Point.hashToPoint(Ed25519Point.G.scalarMultiply(Scalar.intToScalar(n)));
            HpnGLookup.put(n, HpnG);
        }
        return HpnGLookup.get(n);
    }

    public static Ed25519PointPair ENCeg(Ed25519Point keyImage, Scalar secretKey) {
        return new Ed25519PointPair(getHpnGLookup(1).scalarMultiply(secretKey).add(keyImage), Ed25519Point.G.scalarMultiply(secretKey));
    }

}

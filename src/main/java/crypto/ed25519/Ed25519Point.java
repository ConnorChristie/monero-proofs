package crypto.ed25519;

import crypto.Scalar;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import utils.HexEncoder;

import java.security.Security;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import static crypto.CryptoUtil.hashToScalar;

public class Ed25519Point {

    public static ECParameterSpec ecsp;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            ecsp = ECNamedCurveTable.getParameterSpec("curve25519");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Ed25519Point ZERO = new Ed25519Point(ecsp.getCurve().getInfinity());
    public static Ed25519Point BASE_POINT = new Ed25519Point(ecsp.getG());
    public static Ed25519Point G = BASE_POINT;
    public static int scalarMults = 0;
    public static int scalarBaseMults = 0;
    public static String lineRecordingSourceFile = null;
    public static boolean enableLineRecording = false;
    public static Map<Integer, Integer> lineNumberCallFrequencyMap = new TreeMap<>(Integer::compareTo);

    public ECPoint point;

    public Ed25519Point(ECPoint point) {
        this.point = point;
    }

    public Ed25519Point(byte[] a) {
        this.point = ecsp.getCurve().decodePoint(a);
    }

    public static Ed25519Point randomPoint() {
        return BASE_POINT.scalarMultiply(Scalar.randomScalar());
    }

    public static Ed25519Point hashToPoint(byte[] a) {
        return BASE_POINT.scalarMultiply(hashToScalar(a));
    }

    public static Ed25519Point hashToPoint(Ed25519Point a) {
        return hashToPoint(a.toBytes());
    }

    public Ed25519Point scalarMultiply(Scalar a) {
        scalarMults++;
        if (this == BASE_POINT) scalarBaseMults++;

        if (enableLineRecording) {
            Optional<StackTraceElement> optionalCaller = Arrays.stream(new Exception().getStackTrace()).filter(e -> e
                    .getFileName().equals(lineRecordingSourceFile)).findFirst();
            if (optionalCaller.isPresent()) {
                StackTraceElement caller = optionalCaller.get();
                lineNumberCallFrequencyMap.putIfAbsent(caller.getLineNumber(), 0);
                lineNumberCallFrequencyMap.computeIfPresent(caller.getLineNumber(), (key, oldValue) -> oldValue + 1);
            }
        }

        return new Ed25519Point(point.multiply(a.toBigInteger()));
    }

    public Ed25519Point add(Ed25519Point a) {
        return new Ed25519Point(point.add(a.point));
    }

    public Ed25519Point sub(Ed25519Point a) {
        return new Ed25519Point(point.subtract(a.point));
    }

    public byte[] toBytes() {
        return point.getEncoded(true);
    }

    public boolean satisfiesCurveEquation() {
        return true;
    }

    @Override
    public String toString() {
        return HexEncoder.getString(toBytes());
    }

    @Override
    public boolean equals(Object obj) {
        return point.equals(((Ed25519Point) obj).point);
    }
}

package crypto;

import crypto.ed25519.arithmetic.Ed25519EncodedFieldElement;
import crypto.ed25519.arithmetic.Ed25519FieldElement;
import utils.HexEncoder;

import java.math.BigInteger;
import java.util.Arrays;

import static crypto.CryptoUtil.*;

public class Scalar {

    public final static Scalar ZERO = intToScalar(0);
    public final static Scalar ONE = intToScalar(1);
    public final static Scalar TWO = intToScalar(2);
    public final static Scalar MINUS_ONE = intToScalar(-1);
    public byte[] bytes;

    public Scalar(byte[] bytes) {
        this.bytes = bytes;
    }

    public Scalar(String hex) {
        this.bytes = HexEncoder.getBytes(hex);
    }

    public Scalar(BigInteger a) {
        this(scReduce32(getUnsignedLittleEndianByteArrayFromBigInteger(a.mod(l))));
    }

    // use only for small numbers
    public static Scalar intToScalar(int a) {
        return new Scalar(scReduce32(getUnsignedLittleEndianByteArrayFromBigInteger(BigInteger.valueOf(a).mod(l))));
    }

    public static Scalar randomScalar() {
        byte[] s = new byte[32];
        random.nextBytes(s);
        s = scReduce32(s);
        return new Scalar(s);
    }

    public static BigInteger[] scalarArrayToBigIntegerArray(Scalar[] a) {
        BigInteger[] r = new BigInteger[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[i].toBigInteger();
        return r;
    }

    public static void printScalarArray(Scalar[] a) {
        for (int i = 0; i < a.length; i++) {
            System.out.print(a[i].toBigInteger() + "");
            if (i == a.length - 1) System.out.println("");
            else System.out.print(", ");
        }
    }

    public static Scalar[] bigIntegerArrayToScalarArray(BigInteger[] a) {
        int len = a.length;
        Scalar[] r = new Scalar[len];
        for (int i = 0; i < len; i++) {
            r[i] = new Scalar(a[i]);
        }
        return r;
    }

    public Ed25519EncodedFieldElement toEd25519EncodedFieldElement() {
        return new Ed25519EncodedFieldElement(bytes);
    }

    public Ed25519FieldElement toEd25519FieldElement() {
        return new Ed25519EncodedFieldElement(bytes).decode();
    }

    @Override
    public String toString() {
        return HexEncoder.getString(bytes);
    }

    public BigInteger toBigInteger() {
        return getBigIntegerFromUnsignedLittleEndianByteArray(this.bytes);
    }

    @Override
    public boolean equals(Object obj) {
        return Arrays.equals(this.bytes, ((Scalar) obj).bytes);
    }

    public Scalar add(Scalar a) {
        return new Scalar(ensure32BytesAndConvertToLittleEndian(getBigIntegerFromUnsignedLittleEndianByteArray(this
                .bytes).add(getBigIntegerFromUnsignedLittleEndianByteArray(a.bytes)).mod(l).toByteArray()));
    }

    public Scalar sub(Scalar a) {
        return new Scalar(ensure32BytesAndConvertToLittleEndian(getBigIntegerFromUnsignedLittleEndianByteArray(this
                .bytes).subtract(getBigIntegerFromUnsignedLittleEndianByteArray(a.bytes)).mod(l).toByteArray()));
    }

    public Scalar mul(Scalar a) {
        return new Scalar(ensure32BytesAndConvertToLittleEndian(getBigIntegerFromUnsignedLittleEndianByteArray(this
                .bytes).multiply(getBigIntegerFromUnsignedLittleEndianByteArray(a.bytes)).mod(l).toByteArray()));
    }

    public Scalar sq() {
        return new Scalar(ensure32BytesAndConvertToLittleEndian(getBigIntegerFromUnsignedLittleEndianByteArray(this
                .bytes).multiply(getBigIntegerFromUnsignedLittleEndianByteArray(this.bytes)).mod(l).toByteArray()));
    }

    public Scalar pow(int b) {
        Scalar result = Scalar.ONE;
        for (int i = 0; i < b; i++) {
            result = result.mul(this);
        }
        return result;
    }

}

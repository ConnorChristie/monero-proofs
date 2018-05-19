package ringct;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;
import crypto.ed25519.Ed25519PointPair;
import utils.HexEncoder;

import static crypto.CryptoUtil.ENCeg;
import static crypto.Scalar.randomScalar;

public class KeyPair {

    public SpendKey spendKey;
    public Ed25519Point keyImage;
    public Ed25519PointPair publicKey;

    public KeyPair(SpendKey spendKey, Ed25519Point keyImage, Ed25519PointPair publicKey) {
        this.spendKey = spendKey;
        this.keyImage = keyImage;
        this.publicKey = publicKey;
    }

    public static KeyPair generateRandom() {
        SpendKey spendKey = new SpendKey(randomScalar(), randomScalar());
        Ed25519Point keyImage = Ed25519Point.G.scalarMultiply(spendKey.keyImagePrivate);
        Ed25519PointPair publicKey = ENCeg(keyImage, spendKey.privateKey);

        return new KeyPair(spendKey, keyImage, publicKey);
    }

    public SpendKey getSpendKey() {
        return spendKey;
    }

    public Ed25519Point getKeyImage() {
        return keyImage;
    }

    public Ed25519PointPair getPublicKey() {
        return publicKey;
    }

    @Override
    public String toString() {
        return "sk: " + spendKey.toString() + ", ki: " + HexEncoder.getString(keyImage.toBytes()) + ", pk: " + (publicKey == null ?
                "(no pk)"
                : "pk: " + publicKey);
    }

    public static class SpendKey {
        public Scalar privateKey;
        public Scalar keyImagePrivate;

        public SpendKey(Scalar privateKey, Scalar keyImagePrivate) {
            this.privateKey = privateKey;
            this.keyImagePrivate = keyImagePrivate;
        }

        public Ed25519Point getSharedSecret(Ed25519Point outPk) {
            return outPk.scalarMultiply(privateKey);
        }

        @Override
        public String toString() {
            return "(privateKey: " + HexEncoder.getString(privateKey) + ", keyImagePrivate: " + HexEncoder.getString(keyImagePrivate) + ")";
        }
    }
}

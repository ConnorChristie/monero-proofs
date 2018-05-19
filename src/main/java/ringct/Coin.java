package ringct;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;
import ringct.proofs.BulletProof;

import static crypto.CryptoUtil.COMp;
import static crypto.CryptoUtil.hashToScalar;
import static crypto.Scalar.randomScalar;

public class Coin {

    public Scalar amount;
    public Scalar mask;

    public KeyPair amountKey;
    public Ed25519Point commitment;

    public BulletProof bulletProof;

    public Coin(KeyPair amountKey, Scalar amount, Scalar mask) {
        this.amount = amount;
        this.mask = mask;

        this.amountKey = amountKey;
        // 2 * (5 log n+ 13 rounds, 22n + 8 multiplications) (n = 4 parties)
        // 36 rounds, 192 multiplications - [amountG], [maskH]
        // 5  rounds, 11  multiplications - [amountG] + [maskH]
        this.commitment = COMp(amount, mask);
    }

    public static Coin fromInput(KeyPair amountKey, EcdhInfo encryptedInfo, Ed25519Point outPk) {
        Ed25519Point sharedSecret = amountKey.getSpendKey().getSharedSecret(outPk);

        return new Coin(amountKey, encryptedInfo.getAmount(sharedSecret), encryptedInfo.getMask(sharedSecret));
    }

    // Done for each real input and output
    // 1 input, 3 outputs (recipient, change, fee) = 4
    public static Coin newOutput(Scalar amount) {
        KeyPair amountKey = KeyPair.generateRandom();

        // Generate pseudo random secret share of this
        // 0 rounds
        Scalar mask = randomScalar();

        Coin coin = new Coin(amountKey, amount, mask);
        coin.bulletProof = BulletProof.prove(amount, mask);

        return coin;
    }

    public Scalar getAmount() {
        return amount;
    }

    public Scalar getMask() {
        return mask;
    }

    public KeyPair getAmountKey() {
        return amountKey;
    }

    public Ed25519Point getCommitment() {
        return commitment;
    }

    public EcdhInfo getEncryptedInfo(Ed25519Point outPk) {
        return EcdhInfo.encrypt(amount, mask, amountKey.getSpendKey().getSharedSecret(outPk));
    }

    public BulletProof getBulletProof() {
        return bulletProof;
    }

    /**
     * Elliptic curve Diffie Hellman encrypted values
     */
    public static class EcdhInfo {
        private Scalar amountEncrypted;
        private Scalar maskEncrypted;

        public EcdhInfo(Scalar amountEncrypted, Scalar maskEncrypted) {
            this.amountEncrypted = amountEncrypted;
            this.maskEncrypted = maskEncrypted;
        }

        public static EcdhInfo encrypt(Scalar amount, Scalar mask, Ed25519Point sharedSecret) {
            Scalar amountEncrypted = amount.add(hashToScalar(sharedSecret.toBytes()));
            Scalar maskEncrypted = mask.add(hashToScalar(sharedSecret.toBytes()));

            return new EcdhInfo(amountEncrypted, maskEncrypted);
        }

        public Scalar getAmount(Ed25519Point sharedSecret) {
            return amountEncrypted.sub(hashToScalar(sharedSecret.toBytes()));
        }

        public Scalar getMask(Ed25519Point sharedSecret) {
            return maskEncrypted.sub(hashToScalar(sharedSecret.toBytes()));
        }
    }
}

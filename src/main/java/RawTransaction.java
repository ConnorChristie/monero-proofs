import java.math.BigInteger;

public class RawTransaction {

    public RCTSignatures rctSignatures;
    public RCTSigPrunable rctSigPrunable;

    public static class RCTSignatures {
        /**
         * Amount / mask for each output
         */
        public ECDHInfo ecdhInfo;

        /**
         * Public key for each output
         */
        public byte[][] outPk;

        /**
         * Transaction fee
         */
        public BigInteger txnFee;

        /**
         * Signature type (RCTTypeFullBulletproof = 3)
         */
        public int type = 3;
    }

    public static class ECDHInfo {
        /**
         * The output commitment
         */
        public byte[] amount;

        /**
         * The output mask
         */
        public byte[] mask;
    }

    public static class RCTSigPrunable {

    }

}

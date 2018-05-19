package ringct;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;
import org.junit.Test;
import ringct.signatures.SpendSignature;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

import static crypto.CryptoUtil.getHpnGLookup;
import static org.junit.Assert.assertTrue;

public class RingCTSpendTests {

    @Test
    public void spendTest() {
        long startTime = new Date().getTime();

        int testIterations = 1;
        int decompositionBase = 2;
        int decompositionExponent = 6;
        int inputs = 3;

        System.out.println("Ring size: " + Math.pow(decompositionBase, decompositionExponent));
        System.out.println("Inputs: " + inputs);

        long startMs = new Date().getTime();
        SpendParams[] sp = new SpendParams[testIterations];
        for (int i = 0; i < testIterations; i++)
            sp[i] = createTestSpendParams(inputs, decompositionBase, decompositionExponent);
        System.out.println("Spend params generation duration: " + (new Date().getTime() - startMs) + " ms");

        Ed25519Point.scalarMults = 0;
        Ed25519Point.scalarBaseMults = 0;

        startMs = new Date().getTime();
        // create a transaction to spend the outputs, resulting in a signature that proves the authority to send them
        SpendSignature[] spendSignature = new SpendSignature[testIterations];
        for (int i = 0; i < testIterations; i++) spendSignature[i] = sp[i].sign(sp[i].getRingCT());

        System.out.println("Spend signature generation duration: " + (new Date().getTime() - startMs) + " ms");

        byte[][] spendSignatureBytes = new byte[testIterations][];
        for (int i = 0; i < testIterations; i++) {
            spendSignatureBytes[i] = spendSignature[i].toBytes();
            System.out.println("Spend Signature length (bytes):" + spendSignatureBytes[i].length);
        }

        startMs = new Date().getTime();

        System.out.println("Spend ScalarMults: " + Ed25519Point.scalarMults);
        System.out.println("Spend BaseScalarMults: " + Ed25519Point.scalarBaseMults);
        Ed25519Point.scalarMults = 0;
        Ed25519Point.scalarBaseMults = 0;

        //Ed25519GroupElement.enableLineRecording = true;
        Ed25519Point.lineRecordingSourceFile = "StringCT.java";

        // verify the spend transaction
        for (int i = 0; i < testIterations; i++) {
            RingCT ringCT = new RingCT(sp[i].getKeyImages(), sp[i].getPublicKeys(), sp[i].commitments, spendSignature[i].commitment, sp[i].getBulletProofs());

            boolean verified = ringCT.verify(spendSignature[i]);
            System.out.println("verified: " + verified);
            assertTrue(verified);
        }

        System.out.println("Verify ScalarMults: " + Ed25519Point.scalarMults);
        System.out.println("Verify BaseScalarMults: " + Ed25519Point.scalarBaseMults);

        System.out.println("Signature verification duration: " + (new Date().getTime() - startMs) + " ms");

        if (Ed25519Point.enableLineRecording) {
            Ed25519Point.lineNumberCallFrequencyMap.forEach((key, value) -> System.out.println("line: " + key + ", calls: " + value));
        }

        System.out.println("Total duration: " + (new Date().getTime() - startTime) + " ms");
    }

    @Test
    public void sendReceiveAndDecodeOutputs() {
        int decompositionBase = 2;
        int decompositionExponent = 5;

        Coin input = Coin.newOutput(Scalar.intToScalar(10));

        Coin output1 = Coin.newOutput(Scalar.intToScalar(7));
        Coin output2 = Coin.newOutput(Scalar.intToScalar(3));

        SpendParams spendParams = new SpendParams(new Coin[]{input}, new Coin[]{output1, output2}, decompositionBase, decompositionExponent);
        SpendSignature signature = spendParams.sign(spendParams.getRingCT());

        RingCT ringCT = new RingCT(spendParams.getKeyImages(), spendParams.getPublicKeys(), spendParams.commitments, signature.commitment, spendParams.getBulletProofs());
        boolean verified = ringCT.verify(signature);

        System.out.println("verified: " + verified);
        assertTrue(verified);

        // Now use the outputs from above as inputs to a new txn
        KeyPair receiver = KeyPair.generateRandom(); // Contains receiver's public key
        Ed25519Point outPk = output2.getAmountKey().getPublicKey().P2; // The senders public key

        Coin.EcdhInfo ecdhInfo = output2.getEncryptedInfo(receiver.getPublicKey().P2);

        Coin obtainedInput = Coin.fromInput(receiver, ecdhInfo, outPk);
        Coin finalOutput = Coin.newOutput(Scalar.intToScalar(3));

        System.out.println("Obtained input: " + obtainedInput.getAmount().toBigInteger().intValue());

        spendParams = new SpendParams(new Coin[]{obtainedInput}, new Coin[]{finalOutput}, decompositionBase, decompositionExponent);
        signature = spendParams.sign(spendParams.getRingCT());

        ringCT = new RingCT(spendParams.getKeyImages(), spendParams.getPublicKeys(), spendParams.commitments, signature.commitment, spendParams.getBulletProofs());
        verified = ringCT.verify(signature);

        System.out.println("verified: " + verified);
        assertTrue(verified);
    }

    @Test
    public void testSerializeDeserialize() {
        int decompositionBase = 2;
        int decompositionExponent = 5;
        int inputs = 3;

        SpendParams spendParams = createTestSpendParams(inputs, decompositionBase, decompositionExponent);
        RingCT ringCT = spendParams.getRingCT();

        byte[] serializedSig = spendParams.sign(ringCT).toBytes();

        SpendSignature deserializedSig = SpendSignature.fromBytes(serializedSig);

        boolean verified = ringCT.verify(deserializedSig);
        System.out.println("verified: " + verified);
        assertTrue(verified);
    }

    public static SpendParams createTestSpendParams(int inputs, int decompositionBase, int decompositionExponent) {
        // The owned inputs that are going to be spent
        Coin[] realInputs = new Coin[inputs];
        for (int i = 0; i < inputs; i++) {
            realInputs[i] = Coin.newOutput(Scalar.intToScalar((int) (Math.random() * 1000 + 1000)));
        }

        // The new outputs to be created (typically one for the recipient one for change)
        BigInteger fee = BigInteger.valueOf(0); //keep fee as zero for now, to avoid overcomplicating things
        Coin[] outputs = new Coin[2];
        outputs[0] = Coin.newOutput(realInputs[0].amount.sub(Scalar.TWO));
        outputs[1] = Coin.newOutput(Arrays.stream(realInputs)
                .map(Coin::getAmount)
                .reduce(Scalar.ZERO, Scalar::add)
                .sub(outputs[0].amount));

        SpendParams spendParams = new SpendParams(realInputs, outputs, decompositionBase, decompositionExponent);

        Ed25519Point S = realInputs[0].commitment;
        for (int i = 1; i < realInputs.length; i++) S = S.add(realInputs[i].commitment);
        S = S.sub(Ed25519Point.G.scalarMultiply(new Scalar(fee)));
        for (Coin output : outputs) S = S.sub(output.commitment);

        Ed25519Point S1 = getHpnGLookup(1).scalarMultiply(spendParams.getMaskedIndex());

        if (!S.equals(S1)) throw new RuntimeException("S != S'");

        return spendParams;
    }

}

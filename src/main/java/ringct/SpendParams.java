package ringct;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;
import crypto.ed25519.Ed25519PointPair;
import ringct.proofs.BulletProof;
import ringct.proofs.Proof2;
import ringct.signatures.MultiSignature;
import ringct.signatures.SpendSignature;

import java.util.Arrays;

import static utils.ArrayUtils.concat;

public class SpendParams {

    private Coin[] inputs;
    private Coin[] outputs;
    private BulletProof[] bulletProofs;

    private int decompositionBase;
    private int decompositionExponent;

    private int ringSize;
    private int ringIndex;

    public Ed25519Point[] commitments;
    private Ed25519PointPair[][] publicKeys;

    private Scalar maskedIndex;
    private Ed25519Point maskedIndexPoint;

    private RingCT ringCT;

    public SpendParams(Coin[] inputs, Coin[] outputs, int decompositionBase, int decompositionExponent) {
        this.inputs = inputs;
        this.outputs = outputs;
        this.bulletProofs = gatherBulletProofs();

        this.decompositionBase = decompositionBase;
        this.decompositionExponent = decompositionExponent;

        this.ringSize = (int) Math.pow(decompositionBase, decompositionExponent);
        this.ringIndex = (int) Math.floor(Math.random() * ringSize);

        this.publicKeys = gatherPublicKeys(ringIndex);
        this.commitments = gatherCommitments(ringIndex);

        this.maskedIndex = gatherMaskedIndex();
        this.maskedIndexPoint = Ed25519Point.G.scalarMultiply(getMaskedIndex());

        this.ringCT = new RingCT(getKeyImages(), getPublicKeys(), commitments, maskedIndexPoint, bulletProofs);
    }

    /**
     * Gets the confidential transaction
     * @return The ring confidential transaction
     */
    public RingCT getRingCT() {
        return ringCT;
    }

    /**
     * Signs the spending params (transaction) and returns the full signature
     *
     * @return The spend signature
     */
    public SpendSignature sign(RingCT ringCT) {
        Proof2 signature = ringCT.sign(ringIndex, signInputs(ringCT), decompositionBase, decompositionExponent);
        byte[] signedRingCT = concat(signature.toBytes(decompositionBase, decompositionExponent), ringCT.toBytes());

        Scalar[] keyImagePrivates = Arrays.stream(inputs)
                .map(x -> x.getAmountKey().getSpendKey().keyImagePrivate).toArray(Scalar[]::new);

        MultiSignature.Signature multiSig = MultiSignature.sign(signedRingCT, keyImagePrivates, null);

        return new SpendSignature(decompositionBase, decompositionExponent, maskedIndexPoint, signature, multiSig);
    }

    /**
     * Signs the inputs for the given confidential transaction
     *
     * @param ringCT The confidential transaction
     * @return The signature
     */
    private Scalar signInputs(RingCT ringCT) {
        Scalar signature = maskedIndex;

        for (int i = 0; i < inputs.length; i++) {
            signature = signature.add(inputs[i].getAmountKey().getSpendKey().privateKey.mul(ringCT.getSubResult().finalInputs[i]));
        }

        return signature;
    }

    public BulletProof[] getBulletProofs() {
        return bulletProofs;
    }

    /**
     * Public keys for each input in every ring
     */
    public Ed25519PointPair[][] getPublicKeys() {
        return publicKeys;
    }

    /**
     * Gets the key images for every input
     */
    public Ed25519Point[] getKeyImages() {
        return Arrays.stream(inputs)
                .map(Coin::getAmountKey)
                .map(KeyPair::getKeyImage)
                .toArray(Ed25519Point[]::new);
    }

    /**
     * Gets the secret index computed from the (sum of input masks) - (sum of output masks)
     */
    public Scalar getMaskedIndex() {
        return maskedIndex;
    }

    private BulletProof[] gatherBulletProofs() {
        return Arrays.stream(outputs).map(Coin::getBulletProof).toArray(BulletProof[]::new);
    }

    /**
     * Gets the public keys of the inputs
     * Only the secret ring contains valid public keys
     *
     * @param ringIndex The secret ring index
     * @return The public keys for each input in every ring
     */
    private Ed25519PointPair[][] gatherPublicKeys(int ringIndex) {
        Ed25519PointPair[][] publicKeys = new Ed25519PointPair[inputs.length][ringSize];

        for (int input = 0; input < inputs.length; input++) {
            for (int ring = 0; ring < ringSize; ring++) {
                if (ring == ringIndex) {
                    publicKeys[input][ring] = inputs[input].getAmountKey().getPublicKey();
                } else {
                    publicKeys[input][ring] = KeyPair.generateRandom().getPublicKey();
                }
            }
        }

        return publicKeys;
    }

    /**
     * Gets the commitments for every ring
     * Only the ring at ringIndex contains actual commitments
     *
     * @param ringIndex The secret ring index
     * @return The commitments for each ring
     */
    private Ed25519Point[] gatherCommitments(int ringIndex) {
        Ed25519Point[] commitments = new Ed25519Point[ringSize];

        for (int ring = 0; ring < ringSize; ring++) {
            if (ring == ringIndex) {
                Ed25519Point inputSum = Arrays.stream(inputs)
                        .map(Coin::getCommitment)
                        .reduce(Ed25519Point.ZERO, Ed25519Point::add);

                commitments[ring] = Arrays.stream(outputs)
                        .map(Coin::getCommitment)
                        .reduce(inputSum, Ed25519Point::sub);
            } else {
                commitments[ring] = Ed25519Point.randomPoint();
            }
        }

        return commitments;
    }

    /**
     * Computes the masked index which is the (sum of input masks) - (sum of output masks)
     *
     * @return The masked index
     */
    private Scalar gatherMaskedIndex() {
        Scalar inputSum = Arrays.stream(inputs)
                .map(Coin::getMask)
                .reduce(Scalar.ZERO, Scalar::add);

        return Arrays.stream(outputs)
                .map(Coin::getMask)
                .reduce(inputSum, Scalar::sub);
    }

}

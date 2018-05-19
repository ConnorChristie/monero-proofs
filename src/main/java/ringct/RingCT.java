package ringct;

import crypto.Scalar;
import crypto.ed25519.Ed25519Point;
import crypto.ed25519.Ed25519PointPair;
import ringct.proofs.BulletProof;
import ringct.proofs.OptimizedLogBulletproof;
import ringct.proofs.Proof2;
import ringct.signatures.MultiSignature;
import ringct.signatures.SpendSignature;

import java.util.Arrays;

import static crypto.CryptoUtil.fastHash;
import static crypto.CryptoUtil.hashToScalar;
import static utils.ArrayUtils.concat;
import static utils.ByteUtils.longToLittleEndianUint32ByteArray;

public class RingCT {

    private Ed25519Point[] keyImages;
    private Ed25519PointPair[][] publicKeys;
    private Ed25519Point[] commitments;
    private Ed25519Point maskedIndex;
    private byte[] message;

    private SubResult subResult;

    public RingCT(Ed25519Point[] keyImages, Ed25519PointPair[][] publicKeys, Ed25519Point[] commitments, Ed25519Point
            maskedIndex, BulletProof[] bulletProofs) {
        this.keyImages = keyImages;
        this.publicKeys = publicKeys;
        this.commitments = commitments;
        this.maskedIndex = maskedIndex;
        this.message = preHash(bulletProofs);
        this.subResult = computeSub();
    }

    public boolean verify(SpendSignature spendSignature) {
        if (!MultiSignature.verify(concat(spendSignature.signature.toBytes(spendSignature.decompositionBase,
                spendSignature.decompositionExponent), toBytes()), keyImages, spendSignature.multiSig)) {
            System.out.println("MultiSignature.verify failed");
            return false;
        }

        if (!spendSignature.signature.isValid(spendSignature.decompositionBase, subResult.finalCommitments)) {
            System.out.println("Proof2 failed");
            return false;
        }

        return true;
    }

    public Proof2 sign(int ringIndex, Scalar signature, int decompositionBase, int decompositionExponent) {
        return Proof2.prove(subResult.finalCommitments, ringIndex, signature, decompositionBase, decompositionExponent);
    }

    public byte[] toBytes() {
        byte[] r = new byte[0];
        for (Ed25519Point keyImage : keyImages) r = concat(r, keyImage.toBytes());
        for (Ed25519PointPair[] publicKey : publicKeys)
            for (Ed25519PointPair aPublicKey : publicKey) r = concat(r, aPublicKey.toBytes());
        for (Ed25519Point commitment1 : commitments) r = concat(r, commitment1.toBytes());
        r = concat(r, maskedIndex.toBytes());
        if (message != null)
            r = concat(r, message);
        return r;
    }

    public SubResult getSubResult() {
        return subResult;
    }

    private SubResult computeSub() {
        int inputs = publicKeys.length;
        int ringSize = publicKeys[0].length;

        byte[] ctBytes = toBytes();
        Scalar[] finalInputs = new Scalar[inputs];

        Ed25519PointPair[] finalCommitments = new Ed25519PointPair[ringSize];
        Ed25519PointPair[] inputPublicKeys = new Ed25519PointPair[inputs];

        for (int input = 0; input < inputs; input++) {
            inputPublicKeys[input] = new Ed25519PointPair(keyImages[input], Ed25519Point.ZERO);
            finalInputs[input] = hashToScalar(concat(keyImages[input].toBytes(), ctBytes,
                    longToLittleEndianUint32ByteArray(input)));
        }

        for (int ring = 0; ring < ringSize; ring++) {
            finalCommitments[ring] = new Ed25519PointPair(commitments[ring], maskedIndex);

            for (int input = 0; input < inputs; input++) {
                finalCommitments[ring] = finalCommitments[ring].add(publicKeys[input][ring].subtract
                        (inputPublicKeys[input]).multiply(finalInputs[input]));
            }
        }

        return new SubResult(finalInputs, finalCommitments);
    }

    private byte[] preHash(BulletProof[] bulletProofs) {
        byte[] bulletProofHash = fastHash(Arrays.stream(bulletProofs)
                .map(BulletProof::toBytes).reduce(new byte[0], (x, y) -> concat(x, y)));

        return concat(toBytes(), bulletProofHash);
    }

    public static class SubResult {
        public Scalar[] finalInputs;
        public Ed25519PointPair[] finalCommitments;

        private SubResult(Scalar[] finalInputs, Ed25519PointPair[] finalCommitments) {
            this.finalInputs = finalInputs;
            this.finalCommitments = finalCommitments;
        }
    }

}

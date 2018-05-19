package ringct.signatures;

import crypto.ed25519.Ed25519Point;
import cursor.ECCursor;
import ringct.proofs.Proof1;
import ringct.proofs.Proof2;
import utils.VarInt;

import static utils.ArrayUtils.concat;

public class SpendSignature {
    public int decompositionBase;
    public int decompositionExponent;

    public Ed25519Point commitment;

    public Proof2 signature;
    public MultiSignature.Signature multiSig;

    public SpendSignature(int decompositionBase, int decompositionExponent, Ed25519Point maskedIndex, Proof2 signature,
                          MultiSignature.Signature multiSig) {
        this.decompositionBase = decompositionBase;
        this.decompositionExponent = decompositionExponent;
        this.commitment = maskedIndex;
        this.signature = signature;
        this.multiSig = multiSig;
    }

    public byte[] toBytes() {
        byte[] result;
        result = concat(VarInt.writeVarInt(decompositionBase), VarInt.writeVarInt(decompositionExponent));
        result = concat(result, commitment.toBytes(), signature.toBytes(decompositionBase, decompositionExponent),
                multiSig.toBytes());
        return result;
    }

    public static SpendSignature fromBytes(byte[] a) {
        ECCursor cursor = new ECCursor(a);
        int decompositionBase = (int) cursor.readVarInt();
        int decompositionExponent = (int) cursor.readVarInt();
        return new SpendSignature(decompositionBase, decompositionExponent,
                cursor.readGroupElement(),
                new Proof2(
                        new Proof1(cursor.readGroupElement(), cursor.readGroupElement(), cursor.readGroupElement(),
                                cursor.readScalar2DArray(decompositionExponent, decompositionBase - 1), cursor
                                .readScalar(), cursor.readScalar(), null),
                        cursor.readGroupElement(),
                        cursor.readPointPairArray(decompositionExponent), cursor.readScalar()),
                new MultiSignature.Signature(cursor.readGroupElement(), cursor.readScalar()));
    }
}

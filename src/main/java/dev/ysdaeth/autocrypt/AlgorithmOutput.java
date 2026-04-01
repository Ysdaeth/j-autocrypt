package dev.ysdaeth.autocrypt;

import java.util.Arrays;

/**
 * Algorithm output contains algorithm identifier, and encoded bytes.
 * Encoded bytes contains
 * <ol>
 *     <li>Algorithm type byte</li>
 *     <li>Algorithm variant byte</li>
 *     <li>Metadata bytes (optional)</li>
 *     <li>Main bytes</li>
 * </ol>
 * Metadata bytes are optional, managed by the algorithm. Their presence depends on the algorithm implementation.
 * Algorithm type is always the first byte, and algorithm variant is the second byte from the encoded bytes.
 * Encoded bytes are not modified. Since encoded bytes already contain all information, there is no need to save
 * algorithm type or variant, because they are already computed in that byte array.
 */
public class AlgorithmOutput {
    private final AlgorithmIdentifier identifier;
    private final byte[] encoded;

    /**
     * Creates object from the encoded bytes, where first byte is algorithm type,
     * second is algorithm variant, and remaining bytes are algorithm metadata and main bytes. remaining bytes
     * are managed by the algorithm.
     * @param encoded unmodified byte array returned by this instance.
     */
    public AlgorithmOutput(byte[] encoded) {
        byte type = encoded[0];
        byte variant = encoded[1];
        this.identifier = new AlgorithmIdentifier(type,variant);
        this.encoded = encoded;
    }

    public AlgorithmOutput(AlgorithmOutput output) {
        byte type = output.encoded[0];
        byte variant = output.encoded[1];
        this.identifier = new AlgorithmIdentifier(type,variant);
        this.encoded = output.encoded;
    }

    /**
     * Returns reference to the array bytes that contains algorithm identifier, algorithm variant,
     * and main bytes in a computed bytes array.
     * @return encoded bytes with all data and algorithm metadata, along with algorithm identifier
     */
    public byte[] getEncoded() {
        return encoded;
    }

    /**
     * Returns immutable object that contains information about algorithm type and variant
     * @return algorithm identifier
     */
    public AlgorithmIdentifier getIdentifier() {
        return identifier;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof AlgorithmOutput other){
            return Arrays.equals(encoded,other.encoded);
        }
        return false;
    }
}

package dev.ysdaeth.autocrypt;

import java.util.Arrays;

/**
 * Algorithm output contains encoded bytes in the following order:
 * <ol>
 *     <li>Algorithm type byte</li>
 *     <li>Algorithm variant byte</li>
 *     <li>Metadata bytes or byte (optional)</li>
 *     <li>Main byte array</li>
 * </ol>
 * Metadata bytes are optional, managed by the algorithm, their presence depends on the algorithm implementation.
 * Algorithm type byte is always the first byte, algorithm variant is always the second byte in the encoded bytes.
 * Encoded bytes are not modified. Encoded bytes contain computed information about algorithm and output, so there is
 * no need to save algorithm type, variant or algorithm metadata like initial vector, salt, etc.
 */
public class AlgorithmOutput {
    private final AlgorithmIdentifier identifier;
    private final byte[] encoded;

    /**
     * Creates instance from the encoded bytes. Encoded bytes contain first byte as an algorithm type,
     * second byte is the algorithm variant, and remaining bytes are optional algorithm metadata bytes
     * managed by the algorithm and main bytes which may be either hash bytes or encrypted bytes.
     * @param encoded bytes that contain identifier, variant, and remaining algorithm output bytes.
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
            return Arrays.equals(encoded, other.encoded);
        }
        return false;
    }
}

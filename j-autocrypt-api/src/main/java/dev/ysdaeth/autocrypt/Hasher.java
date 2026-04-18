package dev.ysdaeth.autocrypt;

/**
 * Interface for data hashing and verification.
 * Produces {@link AlgorithmOutput}
 * <blockquote><pre>
 *     byte[] message = "Hello".getBytes();
 *
 *     AlgorithmOutput output = hash(message);
 *     boolean verified = matches(message, output);
 * </pre></blockquote>
 */
public interface Hasher extends Cryptographic {
    /**
     * Create hash based on the provided data
     * @param data data to create hash
     * @return bytes wrapped with AlgorithmOutput
     */
    AlgorithmOutput hash(byte[] data);

    /**
     * Tests if data bytes matches created hash
     * @param data data to create hash
     * @param output hash to compare
     * @return true if data matches hash, otherwise false.
     */
    boolean matches(byte[] data, AlgorithmOutput output);
}

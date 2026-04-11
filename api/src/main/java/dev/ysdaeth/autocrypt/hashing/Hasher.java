package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmOutput;

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
public interface Hasher {
}

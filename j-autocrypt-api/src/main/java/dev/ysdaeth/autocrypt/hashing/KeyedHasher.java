package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;

import java.security.Key;
import java.security.KeyException;

/**
 * Interface for data hashing and verification with a secret key.
 * Produces {@link AlgorithmOutput}
 * <blockquote><pre>
 *     byte[] message = "Hello".getBytes();
 *     Key messageKey = ... // create a key
 *
 *     AlgorithmOutput output = sign(message, messageKey);
 *     boolean verified = verify(message, output, messageKey);
 * </pre></blockquote>
 */
public interface KeyedHasher {

    /**
     * Returns wrapped encoded bytes array with {@link AlgorithmOutput}.
     * @param key key used for creating the sign.
     * @param message data to create sign for.
     * @throws KeyException when provided key does not match the algorithm implementation
     * @return encoded bytes array, with algorithm identifier
     */
    AlgorithmOutput hash(byte[] message, Key key) throws KeyException;

    /**
     * Returns true if the message matches the output bytes. Encoded bytes contains
     * @param output wrapper for output bytes.
     * @param key key for the verification
     * @return true if message and key matches the sign, otherwise false.
     * @throws KeyException when key is not initialized, does not match the algorithm, etc.
     */
    boolean matches(byte[] message, AlgorithmOutput output, Key key) throws KeyException;
    AlgorithmIdentifier getIdentifier();
}

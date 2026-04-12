package dev.ysdaeth.autocrypt.encryption;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;

import java.security.Key;
import java.security.KeyException;

/**
 * Encryptor that returns {@link AlgorithmOutput}
 * Metadata bytes are optional and their presence depends on the algorithm implementation
 */
public interface Encryptor {

    /**
     * Encrypts data and returns encoded bytes and returns {@link AlgorithmOutput}.
     * Throws KeyException when key does not match this algorithm instance.
     * @param raw data to encrypt
     * @param key key for encryption
     * @return encoded bytes with metadata and encrypted bytes
     * @throws KeyException When key does not match this algorithm instance
     */
    AlgorithmOutput encrypt(byte[] raw, Key key) throws KeyException;

    /**
     * Decrypts and returns data from the encoded bytes {@link AlgorithmOutput}. Encoded bytes
     * must be produced by the same instance. KeyException is thrown when key does not match the
     * Encryptor instance or can not be used to decrypt encrypted bytes.
     * @param encoded bytes produced by this algorithm instance
     * @param key key used for encryption
     * @return decrypted raw data
     * @throws KeyException when key does not match the secret, or not match the algorithm instance.
     */
    byte[] decrypt(AlgorithmOutput encoded, Key key) throws KeyException;
    AlgorithmIdentifier getIdentifier();

}

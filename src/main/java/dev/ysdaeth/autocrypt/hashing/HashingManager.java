package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.hashing.authenticator.KeyedAuthenticator;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;

/**
 * Creates hashes of the raw input data, or data and a key.
 */
public class HashingManager {

    /**
     * Creates a hash of the raw data provided as an argument by using the provided key.
     * Hashing function is selected by the provided algorithm identifier. It uses
     * {@link KeyedAuthenticator} for data hashing.
     * @param raw data to create a hash
     * @param key key to create a hash
     * @param identifier algorithm of the keyed identifier
     * @return encoded bytes with algorithm identifier, algorithm
     * @throws RuntimeException when algorithm instance could not be provided by the java security provider
     * @throws KeyException when key does not match the algorithm instance
     * @throws AlgorithmIdentificationException When there is no implementation,
     * or provided algorithm can not be used with {@link KeyedAuthenticator}
     */
    public AlgorithmOutput hash(byte[] raw, Key key, AlgorithmIdentifier identifier)
            throws KeyException, AlgorithmIdentificationException {

        KeyedAuthenticator authenticator = KeyedAuthenticator.getInstance(identifier);
        return authenticator.sign(raw,key);
    }

    /**
     * Automatically selects algorithm of the {@link KeyedAuthenticator} used for hashing encoded byte array, and
     * tests if raw data and a key matches the created hash
     * Returns true if data matches the hash, otherwise false.
     * @param raw raw data to check
     * @param output wrapped encoded bytes created by {@link KeyedAuthenticator}
     * @param key key used for hashing encoded bytes
     * @return true if hash matches, otherwise false
     * @throws RuntimeException when algorithm instance could not be provided by the java security provider
     * @throws AlgorithmIdentificationException when provided encoded bytes does not match
     * @throws InvalidKeyException when key is in illegal state like, not initialized, not match the algorithm, etc.
     * any known algorithm used by the {@link KeyedAuthenticator}
     */
    public boolean matches(byte[] raw, AlgorithmOutput output, Key key)
            throws AlgorithmIdentificationException, InvalidKeyException {

        AlgorithmIdentifier identifier = new AlgorithmIdentifier(output.getEncoded());
        KeyedAuthenticator authenticator = KeyedAuthenticator.getInstance(identifier);
        return authenticator.verify(raw,output,key);
    }
}

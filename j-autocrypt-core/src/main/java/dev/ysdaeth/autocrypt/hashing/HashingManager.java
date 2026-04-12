package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.CryptographicRegistry;

import java.security.Key;
import java.security.KeyException;
import java.util.Objects;

/**
 * Creates hashes of the raw input data, or data and a key.
 */
public class HashingManager {

    private final CryptographicRegistry<KeyedHasher> keyedHasherRegistry;
    private final CryptographicRegistry<Hasher> hasherRegistry;

    public HashingManager(
            CryptographicRegistry<KeyedHasher> keyedHasherRegistry,
            CryptographicRegistry<Hasher> hasherRegistry){
        this.keyedHasherRegistry = Objects.requireNonNull(keyedHasherRegistry);
        this.hasherRegistry = hasherRegistry;
    }

    /**
     * Creates a hash of the data provided as an argument by using the provided key.
     * Hashing function is selected by the provided algorithm identifier. It uses
     * {@link KeyedHasher} for data hashing.
     * @param data data to create a hash
     * @param key key to create a hash
     * @param identifier algorithm of the keyed identifier
     * @return encoded bytes with algorithm identifier, algorithm
     * @throws RuntimeException when algorithm instance could not be provided by the security provider
     * @throws KeyException when key does not match the algorithm instance
     * @throws AlgorithmIdentificationException When there is no registered implementation
     * assigned to the {@link AlgorithmIdentifier}
     */
    public AlgorithmOutput hash(byte[] data, Key key, AlgorithmIdentifier identifier)
            throws KeyException, AlgorithmIdentificationException {

        KeyedHasher authenticator = keyedHasherRegistry.getRegistered(identifier);
        return authenticator.hash(data,key);
    }

    /**
     * Creates a hash of the data provided as an argument.
     * Hashing function is selected by the provided algorithm identifier. It uses
     * {@link Hasher} for data hashing.
     * @param data data to create a hash
     * @param identifier algorithm of the keyed identifier
     * @return encoded bytes with algorithm identifier, algorithm
     * @throws RuntimeException when algorithm instance could not be provided by the security provider
     * @throws KeyException when key does not match the algorithm instance
     * @throws AlgorithmIdentificationException When there is no registered implementation
     * assigned to the {@link AlgorithmIdentifier}
     */
    public AlgorithmOutput hash(byte[] data, AlgorithmIdentifier identifier)
            throws KeyException, AlgorithmIdentificationException {

        Hasher hasher = hasherRegistry.getRegistered(identifier);
        return hasher.hash(data);
    }

    /**
     * Automatically selects algorithm of the {@link KeyedHasher} used for hashing encoded byte array, and
     * tests if raw data and a key matches the created hash
     * Returns true if data matches the hash, otherwise false.
     * @param raw raw data to check
     * @param output wrapped encoded bytes created by the {@link KeyedHasher}
     * @param key key used for hashing encoded bytes
     * @return true if hash matches, otherwise false
     * @throws RuntimeException when algorithm instance could not be provided by the java security provider
     * @throws AlgorithmIdentificationException when provided encoded bytes does not match
     * @throws KeyException when key is in illegal state like, not initialized, not match the algorithm, etc.
     * any known algorithm used by the {@link KeyedHasher}
     */
    public boolean matches(byte[] raw, AlgorithmOutput output, Key key)
            throws AlgorithmIdentificationException, KeyException {

        AlgorithmIdentifier identifier = output.getIdentifier();
        KeyedHasher authenticator = keyedHasherRegistry.getRegistered(identifier);
        return authenticator.matches(raw, output, key);
    }

    /**
     * Automatically selects algorithm of the {@link Hasher} used for hashing encoded byte array, and
     * tests if raw data and a key matches the created hash
     * Returns true if data matches the hash, otherwise false.
     * @param raw raw data to check
     * @param output wrapped encoded bytes created by the {@link Hasher}
     * @return true if hash matches, otherwise false
     * @throws RuntimeException when algorithm instance could not be provided by the java security provider
     * @throws AlgorithmIdentificationException when provided encoded bytes does not match
     * any known algorithm used by the {@link Hasher}
     */
    public boolean matches(byte[] raw, AlgorithmOutput output)
            throws AlgorithmIdentificationException {

        AlgorithmIdentifier identifier = output.getIdentifier();
        Hasher authenticator = hasherRegistry.getRegistered(identifier);
        return authenticator.matches(raw, output);
    }
}

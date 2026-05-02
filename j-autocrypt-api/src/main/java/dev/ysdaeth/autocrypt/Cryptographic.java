package dev.ysdaeth.autocrypt;

/**
 * Interface to group algorithm implementations.
 * {@link Hasher}, {@link KeyedHasher}, {@link Encryptor}
 */
public interface Cryptographic {
    /**
     * Returns identifier assigned to this algorithm instance
     * @return identifier
     */
    AlgorithmIdentifier getIdentifier();
}

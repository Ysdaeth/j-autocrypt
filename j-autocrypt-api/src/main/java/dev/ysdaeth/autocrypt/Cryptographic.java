package dev.ysdaeth.autocrypt;

/**
 * Interface to group algorithm implementations.
 * {@link Hasher}, {@link KeyedHasher}, {@link Encryptor}
 */
public interface Cryptographic {
    AlgorithmIdentifier getIdentifier();
}

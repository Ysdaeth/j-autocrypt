package dev.ysdaeth.autocrypt.encryption;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.encryption.aes.AesFactory;

import java.security.Key;
import java.security.KeyException;
import java.util.Objects;

/**
 * Encryptor for data encryption, that encodes encrypted bytes and metadata bytes computed byte array.
 * Encoded bytes contain:
 * <ul>
 *     <li> Algorithm type (1 byte)</li>
 *     <li> Algorithm variant (1 byte)</li>
 *     <li> Algorithm metadata bytes(optional bytes)</li>
 *     <li> Main encrypted bytes array </li>
 * </ul>
 * Metadata bytes are optional and their presence depends on the algorithm implementation
 */
public abstract class Encryptor {

    /**
     * Returns a new instance of the algorithm implementation
     * based on the provided algorithm identifier. Throws Runtime exception when identifier is null
     * @param identifier algorithm identifier with algorithm type and variant.
     * @return AES encryptor instance
     * @throws AlgorithmIdentificationException when there is no encryptor implementation
     * for the specified identifier, or identifier does not match to any encryptor instance
     * @throws RuntimeException sometimes
     */
    public static Encryptor getInstance(AlgorithmIdentifier identifier)
            throws AlgorithmIdentificationException, RuntimeException {
        Objects.requireNonNull(identifier,"Algorithm identifier must not be null");
        byte type = identifier.type();
        if(type == AlgorithmIdentifier.AES) return AesFactory.getInstance(identifier);
        throw new AlgorithmIdentificationException("No such algorithm for encryptor with given identifier: " + identifier);
    }

    /**
     * Encrypts data and returns encoded bytes, that contains algorithm identifier
     * bytes {@link AlgorithmIdentifier}, algorithm metadata bytes, and encrypted bytes.
     * Structure of the encoded bytes:
     * <ul>
     *     <li> algorithm type (1 byte)</li>
     *     <li> algorithm variant (1 byte)</li>
     *     <li> metadata bytes(optional bytes)</li>
     *     <li> main encrypted bytes array </li>
     * </ul>
     * Metadata bytes are optional and their presence depends on the algorithm implementation
     * Throws KeyException when key does not match this algorithm instance
     * @param raw data to encrypt
     * @param key key for encryption
     * @return encoded bytes with metadata and encrypted bytes
     * @throws KeyException When key does not match this algorithm instance
     */
    public abstract AlgorithmOutput encrypt(byte[] raw, Key key) throws KeyException;

    /**
     * Decrypts and returns data from the encoded bytes. Encoded bytes must be produced by the same instance,
     * otherwise KeyException is thrown. KeyException is thrown also when key does not match this algorithm instance,
     * or does not match the encrypted data from encoded bytes.
     * @param encoded bytes produced by this algorithm instance
     * @param key key used for encryption
     * @return decrypted raw data
     * @throws KeyException when key does not match the secret, or not match tke algorithm instance.
     */
    public abstract byte[] decrypt(AlgorithmOutput encoded, Key key) throws KeyException;

}

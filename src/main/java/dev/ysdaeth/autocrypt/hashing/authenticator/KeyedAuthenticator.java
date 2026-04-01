package dev.ysdaeth.autocrypt.hashing.authenticator;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.hashing.authenticator.hmac.HMacFactory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.util.Objects;

/**
 * Abstract class for data signing and verification with a secret key.
 * Produced algorithm output is encoded byte array, that contains:
 * <ol>
 *     <li>Algorithm identifier byte</li>
 *     <li>Algorithm version byte</li>
 *     <li>Metadata bytes (optional)</li>
 *     <li>Encrypted bytes</li>
 * </ol>
 * Metadata bytes are managed by the encryptor instance and their presence is optional.
 * <blockquote><pre>
 *     byte[] message = "Hello".getBytes(StandartCharset.UTF_8);
 *     Key messageKey = // create a key
 *
 *     AlgorithmIdentifier identifier = AlgorithmIdentifier.H_MAC_SHA256
 *     KeyedAuthenticator hmac = KeyedAuthenticator.getInstance(identifier);
 *
 *     byte[] encoded = hmac.sign(message, messageKey);
 *     boolean verified = hmac.verify(message, encoded, messageKey);
 * </pre></blockquote>
 */
public abstract class KeyedAuthenticator {

    /**
     * Returns implementation based on the provided identifier.
     * <blockquote><pre>
     *     AlgorithmIdentifier identifier = AlgorithmIdentifier.hMacSha256()
     *     KeyedAuthenticator hMac = KeyedAuthenticator.getInstance(identifier);
     * </pre></blockquote>
     * @param identifier identifier of the algorithm
     * @return implementation of the keyed authenticator
     * @throws AlgorithmIdentificationException when there is no implementation for algorithm type or variant
     * @throws RuntimeException when algorithm implementation could not be provided by the security provider,
     * or when identifier is null
     * @throws NullPointerException when identifier is null
     */
    public static KeyedAuthenticator getInstance(AlgorithmIdentifier identifier)
            throws RuntimeException, AlgorithmIdentificationException {
        Objects.requireNonNull(identifier,"Algorithm identifier must not be null");
        byte type = identifier.type();
        if(type == AlgorithmIdentifier.H_MAC) return HMacFactory.getInstance(identifier);
        throw new AlgorithmIdentificationException("No such algorithm for keyed authenticator with given identifier: " + identifier);
    }

    /**
     * Returns the encoded bytes array, that contains:
     * <ol>
     *     <li>Algorithm identifier byte</li>
     *     <li>Algorithm version byte</li>
     *     <li>Metadata bytes (optional)</li>
     *     <li>Hash sign bytes </li>
     * </ol>
     * Metadata bytes are managed by the authenticator instance, and are optional. Their presence
     * depends on the algorithm implementation.
     * @param key key used for creating the sign.
     * @param message data to create sign for.
     * @throws KeyException when provided key does not match the algorithm implementation
     * @return encoded bytes array, with algorithm identifier
     */
    public abstract AlgorithmOutput sign(byte[] message, Key key) throws KeyException;

    /**
     * Returns true if the message matches the encoded bytes. Encoded bytes contains
     * <ol>
     *     <li>Algorithm type byte</li>
     *     <li>Algorithm variant byte</li>
     *     <li>Metadata bytes (optional)</li>
     *     <li>Hash sign bytes </li>
     * </ol>
     * @param encoded wrapper for encoded bytes.
     * @param key key for the verification
     * @return true if message and key matches the sign, otherwise false.
     */
    public abstract boolean verify(byte[] message, AlgorithmOutput encoded, Key key) throws InvalidKeyException;
}

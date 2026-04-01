package dev.ysdaeth.autocrypt.hashing.authenticator.hmac;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.hashing.authenticator.KeyedAuthenticator;

import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

class HMacSha extends KeyedAuthenticator {

    private final String cipherInstance;
    private final AlgorithmIdentifier identifier;

    HMacSha(String cipherAlgorithm, AlgorithmIdentifier identifier) {
        this.cipherInstance = Objects.requireNonNull(cipherAlgorithm, "Cipher algorithm must noe be null");
        this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
    }

    /**
     * Creates a hash / sign for message provided as an argument, and includes it in
     * encoded bytes. Encoded bytes contain {@link AlgorithmIdentifier} bytes, and main bytes which are hash bytes.
     * @param message data to create sign for.
     * @param key key used for creating the sign.
     * @return encoded bytes with metadata and hash
     * @throws InvalidKeyException when key is in invalid state like, not initialized, etc.
     */
    @Override
    public AlgorithmOutput sign(byte[] message, Key key) throws InvalidKeyException {
        if(key == null) throw new InvalidKeyException("Key must not be null");
        Mac mac;
        try{
            mac = Mac.getInstance(cipherInstance);
            mac.init(key);
        }catch (NoSuchAlgorithmException e){
            throw new RuntimeException("Failed to obtain Mac instance."+e.getMessage(), e);
        }
        byte[] sign = mac.doFinal(message);
        return new HMacOutput(identifier, sign);
    }

    /**
     * Tests if provided message bytes matches the algorithm output and returns true or false.
     * Throws KeyException if key is in invalid state like, not initialized,
     * or does not match the algorithm instance.
     * @param message message to check hash.
     * @param output this algorithm output created from the message.
     * @param key key used for hashing original message
     * @return true if hash matches, otherwise false.
     */
    @Override
    public boolean verify(byte[] message, AlgorithmOutput output, Key key) throws InvalidKeyException {
        byte[] encodedSource;
        encodedSource = sign(message,key).getEncoded();
        return Arrays.equals(encodedSource,output.getEncoded());
    }

    /**
     * Class HMac output management
     */
    private static class HMacOutput extends AlgorithmOutput {

        HMacOutput(AlgorithmIdentifier identifier, byte[] mainBytes) {
            super(
                    build(identifier, mainBytes)
            );
        }

        /**
         * Create encoded bytes that contains identifier byte, version byte, and sign bytes array,
         * by using ByteBuffer. Total length of the encoded byte array is 1(type) + 1(variant) + mainBytes.length.
         * @param identifier identifier for algorithm that specifies type, and variant of the algorithm.
         * @param mainBytes main bytes of the algorithm that contains metadata, like initialVector, and byte hash.
         *                  main bytes should not contain algorithm identifier bytes.
         * @return encoded bytes array that includes identifier, version, etc.
         */
        private static byte[] build(AlgorithmIdentifier identifier, byte[] mainBytes) {
            // Add 2 bytes to buffer for identifier, and a version.
            ByteBuffer byteBuffer = ByteBuffer.allocate(2 + mainBytes.length)
                    .put(identifier.type())
                    .put(identifier.variant())
                    .put(mainBytes);

            return byteBuffer.array();
        }
    }

}

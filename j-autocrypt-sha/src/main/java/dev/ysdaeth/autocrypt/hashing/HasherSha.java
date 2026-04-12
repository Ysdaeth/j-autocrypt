package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

public class HasherSha implements Hasher {
    private final AlgorithmIdentifier identifier;
    private final String digestInstance;

    private HasherSha(AlgorithmIdentifier identifier,String digestInstance){
        this.identifier = Objects.requireNonNull(identifier,"Algorithm identifier must not be null");
        this.digestInstance = Objects.requireNonNull(digestInstance,"Digest instance must not be null");
    }

    @Override
    public AlgorithmOutput hash(byte[] data) {
        MessageDigest digest;
        try{
            digest = MessageDigest.getInstance(digestInstance);
        }catch (Exception e){
            throw new IllegalStateException(
                    "Failed to obtain instance' " + digestInstance + "'. "+ e.getMessage(), e);
        }
        byte[] encoded = ByteBuffer.allocate(digest.getDigestLength() +2) // +2 bytes for type and variant bytes
                .put(identifier.type())
                .put(identifier.variant())
                .put(digest.digest(data))
                .array();

        return new AlgorithmOutput(encoded);
    }

    @Override
    public boolean matches(byte[] data, AlgorithmOutput output) {
        if(!identifier.equals(output.getIdentifier())) return false;
        byte[] actual = hash(data).getEncoded();
        return Arrays.equals(output.getEncoded(),actual);
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherSha sha224(AlgorithmIdentifier identifier){
        return new HasherSha(identifier,"SHA-224");
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherSha sha256(AlgorithmIdentifier identifier){
        return new HasherSha(identifier,"SHA-256");
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherSha sha384(AlgorithmIdentifier identifier){
        return new HasherSha(identifier,"SHA-384");
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherSha sha512(AlgorithmIdentifier identifier){
        return new HasherSha(identifier,"SHA-512");
    }
}

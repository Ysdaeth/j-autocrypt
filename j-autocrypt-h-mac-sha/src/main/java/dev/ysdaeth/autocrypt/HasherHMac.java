package dev.ysdaeth.autocrypt;

import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyException;

public class HasherHMac implements KeyedHasher {

    private final AlgorithmIdentifier identifier;
    private final String instance;

    private HasherHMac(AlgorithmIdentifier identifier, String instance){
        this.identifier = identifier;
        this.instance = instance;
    }

    /**
     * Creates keyed hash for message. Output contains {@link AlgorithmIdentifier} as leading bytes,
     * and hash bytes contains
     * @param data data to create sign for.
     * @param key key used for creating the sign.
     * @return encoded bytes with metadata and hash
     * @throws KeyException when key is not initialized, does not match the algorithm, etc.
     */
    @Override
    public AlgorithmOutput hash(byte[] data, Key key) throws KeyException {
        Mac mac;
        try{
            mac = Mac.getInstance(instance);
        }catch (Exception e){
            throw new IllegalStateException("Failed to get instance from security provider." + e.getMessage(), e);
        }
        mac.init(key);
        byte[] encoded = ByteBuffer.allocate(mac.getMacLength()+2) // + 2 bytes for type and variant
                .put(identifier.type())
                .put(identifier.variant())
                .put(mac.doFinal(data))
                .array();

        return new AlgorithmOutput(encoded);
    }

    /**
     * Tests if data matches the algorithm encoded bytes.
     * @param data data to create the hash
     * @param encoded hash to compare.
     * @param key key for the verification
     * @return true if matches, or false when does not match
     * @throws KeyException When key is not initialized, does not match the algorithm, etc.
     */
    @Override
    public boolean matches(byte[] data, AlgorithmOutput encoded, Key key) throws KeyException {
        boolean identifierMatches = identifier.equals(encoded.getIdentifier());
        if(!identifierMatches) return false;
        AlgorithmOutput actual = hash(data,key);
        return actual.equals(encoded);
    }


    @Override
    public AlgorithmIdentifier getIdentifier() {
        return identifier;
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherHMac sha224(AlgorithmIdentifier identifier){
        return new HasherHMac(identifier, "HmacSHA224");
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherHMac sha256(AlgorithmIdentifier identifier){
        return new HasherHMac(identifier, "HmacSHA256");
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherHMac sha384(AlgorithmIdentifier identifier){
        return new HasherHMac(identifier, "HmacSHA384");
    }

    /**
     * Creates instance that perform hashing operations, where encoded bytes contains specified algorithm identifier
     * as the leading bytes.
     * @param identifier identifier bytes to include into bytes
     * @return hasher instance
     */
    public static HasherHMac sha512(AlgorithmIdentifier identifier){
        return new HasherHMac(identifier, "HmacSHA512");
    }

}

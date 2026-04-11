package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;

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
     * Creates keyed hash for message.
     * @param message data to create sign for.
     * @param key key used for creating the sign.
     * @return encoded bytes with metadata and hash
     * @throws KeyException when key is not initialized, does not match the algorithm, etc.
     */
    @Override
    public AlgorithmOutput hash(byte[] message, Key key) throws KeyException {
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
                .put(mac.doFinal(message))
                .array();

        return new AlgorithmOutput(encoded);
    }

    /**
     * Tests if message matches the algorithm output bytes.
     * @param message message to create hash
     * @param output hash to compare.
     * @param key key for the verification
     * @return true if matches, or false when does not match
     * @throws KeyException When key is not initialized, does not match the algorithm, etc.
     */
    @Override
    public boolean matches(byte[] message, AlgorithmOutput output, Key key) throws KeyException {
        boolean identifierMatches = identifier.equals(output.getIdentifier());
        if(!identifierMatches) return false;
        AlgorithmOutput actual = hash(message,key);
        return actual.equals(output);
    }


    @Override
    public AlgorithmIdentifier getIdentifier() {
        return identifier;
    }

    public static HasherHMac sha224(){ return new HasherHMac(AlgorithmIdentifier.H_MAC_SHA224, "HmacSHA224");}
    public static HasherHMac sha256(){ return new HasherHMac(AlgorithmIdentifier.H_MAC_SHA256, "HmacSHA256");}
    public static HasherHMac sha384(){ return new HasherHMac(AlgorithmIdentifier.H_MAC_SHA384, "HmacSHA384");}
    public static HasherHMac sha512(){ return new HasherHMac(AlgorithmIdentifier.H_MAC_SHA512, "HmacSHA512");}

}

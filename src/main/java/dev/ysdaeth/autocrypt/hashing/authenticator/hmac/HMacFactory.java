package dev.ysdaeth.autocrypt.hashing.authenticator.hmac;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.hashing.authenticator.KeyedAuthenticator;
import java.util.Objects;

public class HMacFactory {

    /**
     * Returns new instance of the HMac algorithm based on the provided version.
     * @param identifier algorithm identifier.
     * @return new instance of the HMac algorithm.
     * @throws RuntimeException when algorithm instance could not be provided by
     * the {@link java.security.Provider} implementation is missing
     * @throws AlgorithmIdentificationException when algorithm identifier does not match any implementation
     */
    public static KeyedAuthenticator getInstance(AlgorithmIdentifier identifier)
            throws RuntimeException, AlgorithmIdentificationException {

        Objects.requireNonNull(identifier,"Identifier must not be null");
        if(identifier.equals(AlgorithmIdentifier.H_MAC_SHA224) ) return new HMacSha("HmacSha224",identifier);
        if(identifier.equals(AlgorithmIdentifier.H_MAC_SHA256) ) return new HMacSha("HmacSha256",identifier);
        if(identifier.equals(AlgorithmIdentifier.H_MAC_SHA384) ) return new HMacSha("HmacSha384",identifier);
        if(identifier.equals(AlgorithmIdentifier.H_MAC_SHA512) ) return new HMacSha("HmacSha512",identifier);
        throw new AlgorithmIdentificationException("HMac algorithm implementation not found for: "+ identifier);
    }
}

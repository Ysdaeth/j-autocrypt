package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.AlgorithmRegistrationException;
import dev.ysdaeth.autocrypt.encryption.Encryptor;
import dev.ysdaeth.autocrypt.encryption.EncryptorRegistry;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class KeyedHasherRegistry {

    private final Map<AlgorithmIdentifier, Supplier<KeyedHasher>>
            identifierHasherMap = new ConcurrentHashMap<>();

    /**
     * Register KeyedHasher in the algorithm registry. KeyedHasher should return encoded bytes as
     * described {@link AlgorithmOutput}. If hasher is already registered, then {@link AlgorithmRegistrationException}
     * is thrown
     * @param hasher implementation of the keyed hasher algorithm
     */
    public void register(KeyedHasher hasher)
            throws AlgorithmRegistrationException {
        Objects.requireNonNull(hasher,"Hasher must not be null");
        register(()-> hasher);
    }

    /**
     * Register KeyedHasher in the algorithm registry. KeyedHasher should return encoded bytes as
     * described {@link AlgorithmOutput}. If hasher is already registered, then {@link AlgorithmRegistrationException}
     * is thrown. Unlike {@link KeyedHasherRegistry#register(KeyedHasher)} this method allows to
     * create a new instance every time when is invoked, or return reference to the existing object. It calls supplier
     * before registration to get identifier.
     * @param hasher implementation to register
     */
    public void register(Supplier<KeyedHasher> hasher)
            throws AlgorithmRegistrationException {
        Objects.requireNonNull(hasher, "Hasher supplier must not be null");
        AlgorithmIdentifier identifier = hasher.get().getIdentifier();
        boolean exists = identifierHasherMap.putIfAbsent(identifier, hasher) != null;
        if(exists) throw new AlgorithmRegistrationException(
                "Algorithm identifier is already used in the registry: " + identifier);
    }

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
    public KeyedHasher getRegistered(AlgorithmIdentifier identifier)
            throws RuntimeException, AlgorithmIdentificationException {
        Supplier<KeyedHasher> hasher =  identifierHasherMap.get(identifier);
        if(hasher != null) return hasher.get();
        throw new AlgorithmIdentificationException(
                "No such algorithm for keyed authenticator with given identifier: " + identifier);
    }

    /**
     * Returns new instance with registered hashers passed as an arguments
     * @param hashers hashers to register
     * @return registry with registered hashers
     */
    public static KeyedHasherRegistry of(KeyedHasher...hashers){
        KeyedHasherRegistry registry = new KeyedHasherRegistry();
        for(KeyedHasher encryptor: hashers) registry.register(encryptor);
        return registry;
    }


    /**
     * Returns new instance with registered hashers passed as an arguments
     * @param hasherSuppliers hashers to register
     * @return registry with registered hashers
     */
    @SafeVarargs
    public static KeyedHasherRegistry of(Supplier<KeyedHasher> ...hasherSuppliers){
        KeyedHasherRegistry registry = new KeyedHasherRegistry();
        for(Supplier<KeyedHasher> supplier: hasherSuppliers) registry.register(supplier);
        return registry;
    }

}

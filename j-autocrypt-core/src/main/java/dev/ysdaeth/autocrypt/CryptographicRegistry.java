package dev.ysdaeth.autocrypt;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Registry to store algorithm implementations like {@link dev.ysdaeth.autocrypt.encryption.Encryptor},
 * {@link dev.ysdaeth.autocrypt.hashing.KeyedHasher} and {@link dev.ysdaeth.autocrypt.hashing.Hasher} which are assigned
 * to the {@link AlgorithmIdentifier}
 * @param <T> type of cryptographic algorithm
 */
public class CryptographicRegistry<T extends Cryptographic> {

    private final Map<AlgorithmIdentifier, Supplier<T>> implementationMap = new ConcurrentHashMap<>();

    /**
     * Register cryptographic algorithm in the registry. Cryptographic algorithm should return encoded bytes as
     * described {@link AlgorithmOutput}. If the cryptographic algorithm instance is already
     * registered, then throws {@link AlgorithmRegistrationException}
     * @param algorithm cryptographic implementation
     */
    public void register(T algorithm)
            throws AlgorithmRegistrationException {
        Objects.requireNonNull(algorithm,"Hasher must not be null");
        register(()-> algorithm);
    }

    /**
     * Register cryptographic algorithm in the algorithm registry. Algorithm should return encoded bytes as
     * described {@link AlgorithmOutput}. If algorithm is already registered, then {@link AlgorithmRegistrationException}
     * is thrown. Unlike {@link CryptographicRegistry#register(Cryptographic)} this method allows to
     * create a new instance everytime when is invoked, or return reference to the existing object. It invokes the supplier
     * before registration to get identifier.
     * @param algorithm implementation to register
     */
    public void register(Supplier<T> algorithm) throws AlgorithmRegistrationException {
        Objects.requireNonNull(algorithm, "Algorithm supplier must not be null");
        AlgorithmIdentifier identifier = algorithm.get().getIdentifier();

        boolean exists = implementationMap.putIfAbsent(identifier, algorithm) != null;
        if(exists) throw new AlgorithmRegistrationException(
                "Algorithm identifier is already used in the registry: " + identifier);
    }

    /**
     * Returns implementation based on the provided identifier.
     * @param identifier identifier of the algorithm
     * @return implementation of the cryptographic registry
     * @throws AlgorithmIdentificationException when there is no registered implementation for the
     * specified algorithm type or variant
     * @throws RuntimeException when algorithm implementation could not be provided by the security provider,
     * or when identifier is null
     * @throws NullPointerException when identifier is null
     */
    public T getRegistered(AlgorithmIdentifier identifier) throws RuntimeException, AlgorithmIdentificationException {
        Supplier<T> hasher =  implementationMap.get(identifier);
        if(hasher != null) return hasher.get();
        throw new AlgorithmIdentificationException(
                "No such algorithm for keyed authenticator with given identifier: " + identifier);
    }

    /**
     * Returns new instance with registered hashers passed as an arguments
     * @param hashers hashers to register
     * @return registry with registered hashers
     */
    public static <T extends Cryptographic> CryptographicRegistry<T> of(T...hashers){
        CryptographicRegistry<T> registry = new CryptographicRegistry<>();
        for(T encryptor: hashers) registry.register(encryptor);
        return registry;
    }


    /**
     * Returns new instance with registered hashers passed as an arguments
     * @param hasherSuppliers hashers to register
     * @return registry with registered hashers
     */
    @SafeVarargs
    public static <T extends Cryptographic> CryptographicRegistry<T> of(Supplier<T> ...hasherSuppliers){
        CryptographicRegistry<T> registry = new CryptographicRegistry<>();
        for(Supplier<T> supplier: hasherSuppliers) registry.register(supplier);
        return registry;
    }

}

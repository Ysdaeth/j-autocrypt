package dev.ysdaeth.autocrypt.encryption;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.AlgorithmRegistrationException;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class EncryptorRegistry {
    private final Map<AlgorithmIdentifier, Supplier<Encryptor>> identifierEncryptorMap = new ConcurrentHashMap<>();

    /**
     * Register the instance in the registry. Instance should return encoded bytes as
     * described in {@link AlgorithmOutput}. If instance is already registered,
     * then {@link AlgorithmRegistrationException} is thrown
     * @param encryptor implementation of the keyed hasher algorithm
     * @throws AlgorithmRegistrationException when algorithm with specified Algorithm identifier
     * is already registered
     */
    public void register(Encryptor encryptor)
            throws AlgorithmRegistrationException {
        register(()-> encryptor);
    }

    /**
     * Register instance in the algorithm registry. Instance should return encoded bytes as
     * described by {@link AlgorithmOutput}. If instance is already registered, then
     * {@link AlgorithmRegistrationException} is thrown.
     * {@link EncryptorRegistry#register(Encryptor)} this method allows own implementation
     * of the providing instance. It uses supplier before registration to get {@link AlgorithmIdentifier}
     * @param encryptor implementation to register
     * @throws AlgorithmRegistrationException when algorithm with specified Algorithm identifier
     * is already registered
     */
    public void register(Supplier<Encryptor> encryptor)
            throws AlgorithmRegistrationException {
        AlgorithmIdentifier identifier = encryptor.get().getIdentifier();
        boolean exists = identifierEncryptorMap.putIfAbsent(identifier, encryptor) != null;
        if(exists) throw new AlgorithmRegistrationException(
                "Algorithm identifier is already used in the registry: " + identifier);
    }

    /**
     * Returns a new instance of the algorithm implementation
     * based on the provided algorithm identifier. Throws Runtime exception when identifier is null
     * @param identifier algorithm identifier with algorithm type and variant.
     * @return AES encryptor instance
     * @throws AlgorithmIdentificationException when there is no encryptor implementation
     * for the specified identifier, or identifier does not match to any encryptor instance
     * @throws RuntimeException sometimes
     */
    public Encryptor getRegistered(AlgorithmIdentifier identifier)
            throws AlgorithmIdentificationException, RuntimeException {
        Supplier<Encryptor> encryptor =  identifierEncryptorMap.get(identifier);
        if(encryptor != null) return encryptor.get();
        throw new AlgorithmIdentificationException(
                "No such algorithm for encryptor with given identifier: " + identifier);
    }

    /**
     * Returns new instance with registered encryptors passed as an arguments
     * @param encryptors encryptors to register
     * @return registry with registered encryptors
     */
    public static EncryptorRegistry of(Encryptor ...encryptors){
        EncryptorRegistry registry = new EncryptorRegistry();
        for(Encryptor encryptor: encryptors) registry.register(encryptor);
        return registry;
    }


    /**
     * Returns new instance with registered encryptors passed as an arguments
     * @param encryptorSuppliers encryptors to register
     * @return registry with registered encryptors
     */
    @SafeVarargs
    public static EncryptorRegistry of(Supplier<Encryptor> ...encryptorSuppliers){
        EncryptorRegistry registry = new EncryptorRegistry();
        for(Supplier<Encryptor> supplier: encryptorSuppliers) registry.register(supplier);
        return registry;
    }
}

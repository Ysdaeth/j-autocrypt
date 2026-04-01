package dev.ysdaeth.autocrypt.encryption.aes;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.encryption.Encryptor;

import java.util.Objects;

public class AesFactory {

    public static Encryptor getInstance(AlgorithmIdentifier identifier)
            throws AlgorithmIdentificationException {

        Objects.requireNonNull(identifier,"Identifier must not be null");
        if(identifier.equals(AlgorithmIdentifier.AES_GCM)) return new AesGcm(identifier);
        throw new AlgorithmIdentificationException("AES algorithm implementation not found for: "+ identifier);
    }
}

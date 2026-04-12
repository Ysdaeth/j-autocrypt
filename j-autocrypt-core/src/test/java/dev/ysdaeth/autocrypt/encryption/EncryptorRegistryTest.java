package dev.ysdaeth.autocrypt.encryption;

import dev.ysdaeth.autocrypt.*;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

class EncryptorRegistryTest {

    @Test
    void register_shouldNotThrowException_whenAlgorithmIdentifierIsUnique() {
        Encryptor encryptor = new MockedEncryptor_1();

        CryptographicRegistry<Encryptor> registry = new CryptographicRegistry<>();
        assertDoesNotThrow(()->registry.register( encryptor));
    }


    @Test
    void register_shouldThrowException_whenAlgorithmIdentifierIsNotUnique() {
        Encryptor encryptor = new MockedEncryptor_1();

        Encryptor existingEncryptor = new MockedEncryptor_1();
        CryptographicRegistry<Encryptor> registry = new CryptographicRegistry<>();

        registry.register(encryptor);
        assertThrowsExactly(
                AlgorithmRegistrationException.class,
                ()-> registry.register(existingEncryptor)
        );
    }


    @Test
    void getRegistered_shouldNotThrowException_whenRegisterUniqueIdentifier() {
        Encryptor encryptor = new MockedEncryptor_1();
        AlgorithmIdentifier identifier = encryptor.getIdentifier();

        CryptographicRegistry<Encryptor> registry = new CryptographicRegistry<>();
        registry.register(encryptor);

        assertDoesNotThrow(()-> registry.getRegistered(identifier));
    }


    @Test
    void getRegistered_shouldThrowException_whenThereIsNoRegisteredEncryptor() {
        AlgorithmIdentifier identifier = new AlgorithmIdentifier((byte)1, (byte)1);
        CryptographicRegistry<Encryptor> registry = new CryptographicRegistry<>();

        assertThrowsExactly(
                AlgorithmIdentificationException.class,
                ()-> registry.getRegistered(identifier)
        );
    }


    private static final class MockedEncryptor_1 implements Encryptor{

        @Override
        public AlgorithmOutput encrypt(byte[] raw, Key key) throws KeyException {
            return new AlgorithmOutput(new byte[]{1,2,3,4,5});
        }

        @Override
        public byte[] decrypt(AlgorithmOutput encoded, Key key) throws KeyException {
            return new byte[]{6,7,8,9,0};
        }

        @Override
        public AlgorithmIdentifier getIdentifier() {
            return new AlgorithmIdentifier((byte)1, (byte)1);
        }
    }
}
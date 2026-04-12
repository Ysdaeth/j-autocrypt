package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.*;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

class KeyedHasherRegistryTest {

    @Test
    void register_shouldNotThrowException_whenIdentifierIsUnique(){
        KeyedHasher hasher = new MockedKeyedHasher();
        CryptographicRegistry<KeyedHasher> registry = new CryptographicRegistry<>();

        assertDoesNotThrow(()->registry.register(hasher));
    }

    @Test
    void register_shouldThrowException_whenIdentifierIsNotUnique() throws Exception {
        KeyedHasher hasher = new MockedKeyedHasher();
        CryptographicRegistry<KeyedHasher> registry = new CryptographicRegistry<>();
        registry.register(hasher);

        assertThrowsExactly(
                AlgorithmRegistrationException.class,
                ()->registry.register(hasher)
        );
    }

    @Test
    void getRegistered_shouldNotThrowException_whenIdentifierExist() throws Exception {
        CryptographicRegistry<KeyedHasher> registry = new CryptographicRegistry<>();
        KeyedHasher hasher = new MockedKeyedHasher();
        AlgorithmIdentifier identifier = hasher.getIdentifier();
        registry.register(hasher);

        assertDoesNotThrow(()->registry.getRegistered(identifier));
    }

    @Test
    void getRegistered_shouldThrowException_whenIdentifierNotRegistered(){
        AlgorithmIdentifier identifier = new AlgorithmIdentifier((byte)2, (byte)2);
        CryptographicRegistry<KeyedHasher> registry = new CryptographicRegistry<>();

        assertThrowsExactly(
                AlgorithmIdentificationException.class,
                ()->registry.getRegistered(identifier)
        );
    }


    private static final class MockedKeyedHasher implements KeyedHasher {

        @Override
        public AlgorithmOutput hash(byte[] message, Key key) throws KeyException {
            return null;
        }

        @Override
        public boolean matches(byte[] message, AlgorithmOutput output, Key key) throws InvalidKeyException {
            return false;
        }

        @Override
        public AlgorithmIdentifier getIdentifier() {
            return new AlgorithmIdentifier((byte)2, (byte)2);
        }
    }

}
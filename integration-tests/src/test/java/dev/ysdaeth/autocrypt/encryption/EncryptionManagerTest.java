package dev.ysdaeth.autocrypt.encryption;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.Identifiers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.security.Key;

public class EncryptionManagerTest {

    @Test
    void encrypt_shouldBeReversibleOperation_AesGcm() throws Exception {
        EncryptionManager manager = createManager();
        Key secretKey = KeyGenerator.getInstance("AES").generateKey();

        byte[] expected = "secret".getBytes();
        byte[] encrypted = manager.encrypt(expected,secretKey,Identifiers.AES_GCM).getEncoded();
        byte[] actual = manager.decrypt(new AlgorithmOutput(encrypted), secretKey);

        Assertions.assertArrayEquals(expected,actual,"Secret is changed after decryption");
    }

    @Test
    void encrypt_shouldReturnProperIdentifier_AesGcm() throws Exception {
        EncryptionManager manager = createManager();
        Key secretKey = KeyGenerator.getInstance("AES").generateKey();

        byte[] expected = "secret".getBytes();
        AlgorithmIdentifier actualIdentifier = manager.encrypt(expected,secretKey,Identifiers.AES_GCM).getIdentifier();

        Assertions.assertEquals(Identifiers.AES_GCM, actualIdentifier, "Invalid algorithm identifier after encryption with AES GCM");
    }

    @Test
    void encrypt_shouldNotThrowAlgorithmIdentifierException_AesGcm() throws Exception {
        EncryptionManager manager = createManager();
        Key secretKey = KeyGenerator.getInstance("AES").generateKey();

        byte[] expected = "secret".getBytes();
        Assertions.assertDoesNotThrow(
                ()->manager.encrypt(expected, secretKey, Identifiers.AES_GCM)
        );
    }

    static EncryptionManager createManager(){
        EncryptorRegistry registry = EncryptorRegistry.of( new EncryptorAesGcm(Identifiers.AES_GCM) );
        return new EncryptionManager(registry);
    }
}

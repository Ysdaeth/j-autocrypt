package dev.ysdaeth.autocrypt.encryption;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.security.Key;

public class EncryptionManagerTest {

    @Test
    void encrypt_shouldBeReversibleOperation_AesGcm() throws Exception {
        EncryptionManager manager = createManager();
        AlgorithmIdentifier identifier = AlgorithmIdentifier.AES_GCM;
        Key secretKey = KeyGenerator.getInstance("AES").generateKey();

        byte[] expected = "secret".getBytes();
        byte[] encrypted = manager.encrypt(expected,secretKey,identifier).getEncoded();
        byte[] actual = manager.decrypt(new AlgorithmOutput(encrypted), secretKey);

        Assertions.assertArrayEquals(expected,actual,"Secret is changed after decryption");
    }

    @Test
    void encrypt_shouldReturnProperIdentifier_AesGcm() throws Exception {
        EncryptionManager manager = createManager();
        AlgorithmIdentifier expectedIdentifier = AlgorithmIdentifier.AES_GCM;
        Key secretKey = KeyGenerator.getInstance("AES").generateKey();

        byte[] expected = "secret".getBytes();
        AlgorithmIdentifier actualIdentifier = manager.encrypt(expected,secretKey,expectedIdentifier).getIdentifier();

        Assertions.assertEquals(expectedIdentifier, actualIdentifier, "Invalid algorithm identifier after encryption with AES GCM");
    }

    @Test
    void encrypt_shouldNotThrowAlgorithmIdentifierException_AesGcm() throws Exception {
        EncryptionManager manager = createManager();
        Key secretKey = KeyGenerator.getInstance("AES").generateKey();

        byte[] expected = "secret".getBytes();
        Assertions.assertDoesNotThrow(
                ()->manager.encrypt(expected, secretKey, AlgorithmIdentifier.AES_GCM)
        );
    }

    static EncryptionManager createManager(){
        EncryptorRegistry registry = EncryptorRegistry.of( EncryptorAesGcm::new );
        return new EncryptionManager(registry);
    }
}

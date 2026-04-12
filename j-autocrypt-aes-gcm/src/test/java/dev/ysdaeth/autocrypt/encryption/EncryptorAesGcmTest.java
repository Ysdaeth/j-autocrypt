package dev.ysdaeth.autocrypt.encryption;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import io.github.ysdaeth.utils.array.ArrayMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.KeyException;
import java.util.Random;

class EncryptorAesGcmTest {
    private static final AlgorithmIdentifier aesIdentifier = new AlgorithmIdentifier((byte)0x01,(byte)0x06);
    EncryptorAesGcm aesGcm = new EncryptorAesGcm(aesIdentifier);

    @Test
    void encrypt_shouldNotContainUnencryptedData() throws Exception{
        byte[] raw = "message".getBytes();
        Key key = KeyGenerator.getInstance("AES").generateKey();
        AlgorithmOutput output = aesGcm.encrypt(raw,key);
        byte[] encoded = output.getEncoded();
        int actualIndex = ArrayMatcher.indexOfSubarray(encoded,raw);
        Assertions.assertEquals(-1,actualIndex, "Encoded bytes should not contain raw data");
    }

    @Test
    void decrypt_shouldReturnDecryptedData() throws Exception {
        Random random = new Random();
        for(int i = 0; i<50_000; i++){
            int arraySize = random.nextInt(1000);
            byte[] expected = new byte[arraySize];
            random.nextBytes(expected);
            Key key = KeyGenerator.getInstance("AES").generateKey();
            AlgorithmOutput output = aesGcm.encrypt(expected,key);
            byte[] actual = aesGcm.decrypt(output, key);
            Assertions.assertArrayEquals(expected, actual, "data bytes should be equal after decryption");
        }
    }

    @Test
    void decrypt_shouldReturnProperAlgorithmIdentifierBytes() throws Exception {
        byte[] raw = "message".getBytes();
        Key key = KeyGenerator.getInstance("AES").generateKey();
        AlgorithmOutput output = aesGcm.encrypt(raw,key);
        byte[] encoded = output.getEncoded();

        AlgorithmIdentifier expectedIdentifier = new AlgorithmIdentifier(aesIdentifier.type(),aesIdentifier.variant());
        Assertions.assertEquals(encoded[0],expectedIdentifier.type(), "data bytes should be equal after decryption");
        Assertions.assertEquals(encoded[1],expectedIdentifier.variant(), "data bytes should be equal after decryption");
    }

    @Test
    void decrypt_shouldThrowKeyException_whenKeyDoesNotMatch() throws Exception {
        byte[] expected = "message".getBytes();
        Key key = KeyGenerator.getInstance("AES").generateKey();
        Key wrongKey = KeyGenerator.getInstance("AES").generateKey();
        AlgorithmOutput output = aesGcm.encrypt(expected,key);

        Assertions.assertThrowsExactly(KeyException.class,()->{
            aesGcm.decrypt(output, wrongKey);
        });
    }

}
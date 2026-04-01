package dev.ysdaeth.autocrypt.hashing.authenticator.hmac;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.util.Base64;

import static dev.ysdaeth.autocrypt.AlgorithmIdentifier.*;

class HMacShaTest {

    final byte[] message = "message".getBytes(StandardCharsets.UTF_8);
    final Key key = toKey("FwGkUtmdsuOiIUvtv7Pg99pHSvc7hCFUD3EnBkmUii0=");
    final byte[] expectedBytes = toEncoded("AAAULwrO5Xm9EcIbxM+c2Vnqzi7SAjw5RjzIN3Z6gkuTWQ==", H_MAC_SHA256);
    final HMacSha hMacSha;

    HMacShaTest() throws Exception{
        hMacSha = (HMacSha) HMacFactory.getInstance(H_MAC_SHA256);
    }

    @Test
    void sign_shouldReturnExpected() throws Exception {
        byte[] actualBytes = hMacSha.sign(message, key).getEncoded();
        Assertions.assertArrayEquals(expectedBytes, actualBytes);
    }

    @Test
    void verify_shouldReturnTrue() throws Exception {
        AlgorithmOutput output = new AlgorithmOutput(expectedBytes);
        boolean isVerified = hMacSha.verify(message,output,key);
        Assertions.assertTrue(isVerified,"Verification should return true when the key and message matches the encoded");
    }

    @Test
    void verify_shouldReturnFalse() throws Exception {
        AlgorithmOutput output = new AlgorithmOutput(new byte[]{1,1,3,4,5,6,7});
        boolean isVerified = hMacSha.verify(message,output,key);
        Assertions.assertFalse(isVerified,"Verification should return false when message does not match the encoded");
    }

    @Test
    void verify_shouldReturnFalseOnWrongKey() throws Exception {
        Key wrongKey = KeyGenerator.getInstance("HmacSha256").generateKey();
        AlgorithmOutput output = new AlgorithmOutput(expectedBytes);
        boolean isVerified = hMacSha.verify(message,output,wrongKey);
        Assertions.assertFalse(isVerified,"Verify should return false when key is incorrect");
    }

    @Test
    void verify_shouldThrowKeyExceptionOnNullKey(){
        AlgorithmOutput output = new AlgorithmOutput(expectedBytes);
        Assertions.assertThrowsExactly(InvalidKeyException.class,
                ()->hMacSha.verify(message, output, null),"Null key should throw exactly KeyException"
        );
    }


    // === UTILS ===

    private static Key toKey(String base64){
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        return new SecretKeySpec(keyBytes,"");
    }

    private static byte[] toEncoded(String bse64, AlgorithmIdentifier identifier){
        byte[] encoded = Base64.getDecoder().decode(bse64);
        encoded[0] = identifier.type();
        encoded[1] = identifier.variant();
        return encoded;
    }
}
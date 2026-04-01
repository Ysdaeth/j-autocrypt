package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.stream.Stream;

class HashingManagerTest {

    HashingManager hashingManager = new HashingManager();

    @ParameterizedTest
    @MethodSource("identifiers")
    void hash_withKey_shouldReturnProperIdentifierBytes(AlgorithmIdentifier identifier) throws Exception {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        Key key = KeyGenerator.getInstance("HmacSha256").generateKey();
        byte[] encoded = hashingManager.hash(message,key,identifier).getEncoded();
        byte type = encoded[0];
        byte variant = encoded[1];
        Assertions.assertEquals(type, identifier.type(),"First byte should be algorithm type");
        Assertions.assertEquals(variant, identifier.variant(),"Second byte should be algorithm variant");
    }

    @ParameterizedTest
    @MethodSource("hashArgs")
    void matches_withKey_shouldDetectAlgorithmAndReturnTrue(Key key, AlgorithmIdentifier identifier) throws Exception {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        AlgorithmOutput encoded = hashingManager.hash(message, key, identifier);
        boolean matches = hashingManager.matches(message,encoded,key);
        Assertions.assertTrue(matches,"Matches should detect algorithm and return true");
    }


    static Stream<AlgorithmIdentifier> identifiers(){
        return Stream.of(
                AlgorithmIdentifier.H_MAC_SHA224,
                AlgorithmIdentifier.H_MAC_SHA256,
                AlgorithmIdentifier.H_MAC_SHA384,
                AlgorithmIdentifier.H_MAC_SHA512
        );
    }

    static Stream<Arguments> hashArgs() throws Exception {
        return Stream.of(
                Arguments.of(KeyGenerator.getInstance("HmacSha224").generateKey(), AlgorithmIdentifier.H_MAC_SHA224),
                Arguments.of(KeyGenerator.getInstance("HmacSha256").generateKey(), AlgorithmIdentifier.H_MAC_SHA256),
                Arguments.of(KeyGenerator.getInstance("HmacSha384").generateKey(), AlgorithmIdentifier.H_MAC_SHA384),
                Arguments.of(KeyGenerator.getInstance("HmacSha512").generateKey(), AlgorithmIdentifier.H_MAC_SHA512)
        );
    }

}
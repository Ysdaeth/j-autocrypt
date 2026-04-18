package dev.ysdaeth.autocrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.stream.Stream;

public class HashingManagerTest {

    @ParameterizedTest
    @MethodSource("keyedHasherIdentifierWithKeyProvider")
    void matches_withKey_shouldReturnTrue(AlgorithmIdentifier identifier, Key hashingKey) throws Exception{
        HashingManager manager = createManager();
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);

        AlgorithmOutput output = manager.hash(message,hashingKey, identifier);

        boolean matches = manager.matches(message, output, hashingKey);
        Assertions.assertTrue(matches, "matches should return true when message and hash matches for identifier: "+ identifier);
    }

    @ParameterizedTest
    @MethodSource("hasherIdentifierProvider")
    void matches_withoutKey_shouldReturnTrue(AlgorithmIdentifier identifier) throws Exception{
        HashingManager manager = createManager();
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);

        AlgorithmOutput output = manager.hash(message, identifier);

        boolean matches = manager.matches(message, output);
        Assertions.assertTrue(matches, "matches should return true when message and hash matches for identifier: "+ identifier);
    }



    static Stream<AlgorithmIdentifier> hasherIdentifierProvider(){
        return Stream.of(
                Identifiers.SHA224, Identifiers.SHA256, Identifiers.SHA384, Identifiers.SHA512
        );
    }
    static Stream<Arguments> keyedHasherIdentifierWithKeyProvider() throws Exception{
        return Stream.of(
                Arguments.of(Identifiers.H_MAC_SHA224 ,KeyGenerator.getInstance("HmacSHA224").generateKey()),
                Arguments.of(Identifiers.H_MAC_SHA256 ,KeyGenerator.getInstance("HmacSHA256").generateKey()),
                Arguments.of(Identifiers.H_MAC_SHA384 ,KeyGenerator.getInstance("HmacSHA384").generateKey()),
                Arguments.of(Identifiers.H_MAC_SHA512 ,KeyGenerator.getInstance("HmacSHA512").generateKey())
        );
    }

    static HashingManager createManager(){
        CryptographicRegistry<KeyedHasher> keyedHasherRegistry = CryptographicRegistry.of(
                HasherHMac.sha224(Identifiers.H_MAC_SHA224),
                HasherHMac.sha256(Identifiers.H_MAC_SHA256),
                HasherHMac.sha384(Identifiers.H_MAC_SHA384),
                HasherHMac.sha512(Identifiers.H_MAC_SHA512)
        );

        CryptographicRegistry<Hasher> hasherRegistry = CryptographicRegistry.of(
                HasherSha.sha224(Identifiers.SHA224),
                HasherSha.sha256(Identifiers.SHA256),
                HasherSha.sha384(Identifiers.SHA384),
                HasherSha.sha512(Identifiers.SHA512)
        );

        return new HashingManager(keyedHasherRegistry, hasherRegistry);
    }
}

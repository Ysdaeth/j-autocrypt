package dev.ysdaeth.autocrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

public class HashingManagerTest {

    static HashingManager manager;
    static {
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
                HasherSha.sha512(Identifiers.SHA512),
                HasherArgon2.argon2i(Identifiers.ARGON2I, 2, 1, 66536, 64),
                HasherArgon2.argon2d(Identifiers.ARGON2D, 2, 1, 66536, 64),
                HasherArgon2.argon2id(Identifiers.ARGON2ID, 2, 1, 66536, 64)
        );
        manager = new HashingManager(keyedHasherRegistry, hasherRegistry);
    }

    static Stream<AlgorithmIdentifier> nonKeyedHasherIdentifiers(){
        return Stream.of(
                Identifiers.SHA224, Identifiers.SHA256, Identifiers.SHA384,
                Identifiers.SHA512, Identifiers.ARGON2D, Identifiers.ARGON2I,
                Identifiers.ARGON2ID
        );
    }
    static Stream<AlgorithmIdentifier> keyedHasherIdentifiers() throws Exception{
        return Stream.of(
                Identifiers.H_MAC_SHA224, Identifiers.H_MAC_SHA256, Identifiers.H_MAC_SHA384, Identifiers.H_MAC_SHA512
        );
    }

    @ParameterizedTest
    @MethodSource("keyedHasherIdentifiers")
    void matches_withKey_shouldReturnTrue_whenHashMatches(AlgorithmIdentifier identifier) throws Exception {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        SecretKey hashingKey = Identifiers.generateKey(identifier);
        AlgorithmOutput output = manager.hash(message, identifier, hashingKey);

        boolean matches = manager.matches(message, output, hashingKey);
        Assertions.assertTrue(matches, "matches should return true when message and hash matches. Identifier: "+ identifier);
    }

    @ParameterizedTest
    @MethodSource("keyedHasherIdentifiers")
    void matches_withKey_shouldReturnFalse_whenHashDoesNotMach(AlgorithmIdentifier identifier) throws Exception {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        SecretKey hashingKey = Identifiers.generateKey(identifier);

        byte[] incorrectHash = new byte[]{identifier.type(), identifier.variant(), 1, 2};
        AlgorithmOutput output = new AlgorithmOutput(incorrectHash);

        boolean matches = manager.matches(message, output, hashingKey);
        Assertions.assertFalse(matches, "matches should return false when message and hash does not match. Identifier: "+ identifier);
    }

    @ParameterizedTest
    @MethodSource("nonKeyedHasherIdentifiers")
    void matches_withoutKey_shouldReturnTrue_whenHashMatches(AlgorithmIdentifier identifier) throws Exception {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);

        AlgorithmOutput output = manager.hash(message, identifier);

        boolean matches = manager.matches(message, output);
        Assertions.assertTrue(matches, "matches should return true when message and hash matches. Identifier: "+ identifier);
    }

    @ParameterizedTest
    @MethodSource("nonKeyedHasherIdentifiers")
    void matches_withoutKey_shouldReturnFalse_whenHashDoesNotMatch(AlgorithmIdentifier identifier) throws Exception {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);

        byte[] incorrectHash = new byte[]{identifier.type(), identifier.variant(), 1, 2};
        AlgorithmOutput output = new AlgorithmOutput(incorrectHash);

        boolean matches = manager.matches(message, output);
        Assertions.assertFalse(matches, "matches should return false when message and hash does not match. Identifier: "+ identifier);
    }
}

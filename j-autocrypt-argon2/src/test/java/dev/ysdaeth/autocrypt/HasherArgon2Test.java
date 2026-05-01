package dev.ysdaeth.autocrypt;

import io.github.ysdaeth.utils.array.ArrayMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class HasherArgon2Test {

    @ParameterizedTest
    @MethodSource("argonProvider")
    void hash_shouldNotContainRawData(HasherArgon2 argon2){
        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        AlgorithmOutput output =  argon2.hash(password);
        byte[] encoded = output.getEncoded();
        int rawIndex = ArrayMatcher.indexOfSubarray(encoded, password);
        Assertions.assertEquals(-1, rawIndex, "Encoded bytes should not contain raw data");
    }

    @ParameterizedTest
    @MethodSource("argonProvider")
    void matches_shouldReturnTrue(HasherArgon2 argon2){
        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        AlgorithmOutput output =  argon2.hash(password);
        boolean matches = argon2.matches(password,output);
        Assertions.assertTrue(matches,"Matches should return true for encoded bytes");
    }

    @Test
    void matches_shouldReturnTrue_whenPropertiesChange_forArgon2id(){
        AlgorithmIdentifier identifier = new AlgorithmIdentifier((byte)0x01,(byte) 0x01);

        HasherArgon2 hasher = HasherArgon2.argon2id(identifier, 2, 1, 66536, 32);
        HasherArgon2 verifier = HasherArgon2.argon2id(identifier, 2, 1, 66536>>>1, 16);

        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        AlgorithmOutput output =  hasher.hash(password);

        boolean matches = verifier.matches(password,output);
        Assertions.assertTrue(matches, "Matches should return true when properties change");
    }

    @Test
    void matches_shouldReturnTrue_whenPropertiesChange_forArgon2i(){
        AlgorithmIdentifier identifier = new AlgorithmIdentifier((byte)0x01,(byte) 0x01);

        HasherArgon2 hasher = HasherArgon2.argon2i(identifier, 2, 1, 66536, 32);
        HasherArgon2 verifier = HasherArgon2.argon2i(identifier, 2, 1, 66536>>>1, 16);

        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        AlgorithmOutput output =  hasher.hash(password);

        boolean matches = verifier.matches(password,output);
        Assertions.assertTrue(matches, "Matches should return true when properties change");
    }

    @Test
    void matches_shouldReturnTrue_whenPropertiesChange_forArgon2d(){
        AlgorithmIdentifier identifier = new AlgorithmIdentifier((byte)0x01,(byte) 0x01);

        HasherArgon2 hasher = HasherArgon2.argon2d(identifier, 2, 1, 66536, 32);
        HasherArgon2 verifier = HasherArgon2.argon2d(identifier, 2, 1, 66536>>>1, 16);

        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        AlgorithmOutput output =  hasher.hash(password);

        boolean matches = verifier.matches(password,output);
        Assertions.assertTrue(matches, "Matches should return true when properties change");
    }


    static Stream<HasherArgon2> argonProvider(){
        AlgorithmIdentifier identifier = new AlgorithmIdentifier((byte)0x01, (byte) 0x01);
        return Stream.of(
                HasherArgon2.argon2id(identifier, 2, 1, 66536, 32),
                HasherArgon2.argon2i(identifier, 2, 1, 66536, 32),
                HasherArgon2.argon2d(identifier, 2, 1, 66536, 32)
        );
    }

}
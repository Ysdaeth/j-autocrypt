package dev.ysdaeth.autocrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Supplier;

class HasherShaTest {
    private static Supplier<byte[]> message = ()->"message".getBytes(StandardCharsets.UTF_8);

    final AlgorithmIdentifier identifierSha224 = new AlgorithmIdentifier((byte) 0x81,(byte) 0x02);
    final AlgorithmIdentifier identifierSha256 = new AlgorithmIdentifier((byte) 0x81,(byte) 0x03);
    final AlgorithmIdentifier identifierSha384 = new AlgorithmIdentifier((byte) 0x81,(byte) 0x04);
    final AlgorithmIdentifier identifierSha512 = new AlgorithmIdentifier((byte) 0x81,(byte) 0x05);

    @Test
    void hash_shouldReturnExpectedBytes_SHA224(){
        byte[] expected = Base64.getDecoder().decode("gQL/Ud36uxgBSFg7pqwjSDrNLQSefE/bpqiRQZMg");
        byte[] actual = HasherSha.sha224(identifierSha224).hash(message.get()).getEncoded();
        Assertions.assertArrayEquals(expected,actual,"hash should return expected bytes");
    }

    @Test
    void hash_shouldReturnExpectedBytes_SHA256(){
        byte[] expected = Base64.getDecoder().decode("gQOrUwoT5FkUmCt5+bfj+6mUz9Hz+yL3HOoa+/ArRgxtHQ==");
        byte[] actual = HasherSha.sha256(identifierSha256).hash(message.get()).getEncoded();
        Assertions.assertArrayEquals(expected,actual,"hash should return expected bytes");
    }

    @Test
    void hash_shouldReturnExpectedBytes_SHA384(){
        byte[] expected = Base64.getDecoder().decode(
                "gQQ1PrdRaifvkultGjGXEthLkC6qgogZ5TqLCa9wKBA6mXi6j+thYeM8NhnF2kxGZqU=");
        byte[] actual = HasherSha.sha384(identifierSha384).hash(message.get()).getEncoded();
        Assertions.assertArrayEquals(expected,actual,"hash should return expected bytes");
    }

    @Test
    void hash_shouldReturnExpectedBytes_SHA512(){
        byte[] expected = Base64.getDecoder().decode(
                "gQX42vV6M0fMTWudV1sx/mB34stIf2CpYjPAjLR52/MVOMyRXsbUi9uqlt3BoW209PlvNyds/LNRC4JGJBdw1ZUs");
        byte[] actual = HasherSha.sha512(identifierSha512).hash(message.get()).getEncoded();
        Assertions.assertArrayEquals(expected,actual,"hash should return expected bytes");
    }

}
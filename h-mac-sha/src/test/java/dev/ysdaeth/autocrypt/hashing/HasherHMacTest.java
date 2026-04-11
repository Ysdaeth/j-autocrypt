package dev.ysdaeth.autocrypt.hashing;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.stream.Stream;

class HasherHMacTest {

    @ParameterizedTest
    @MethodSource("hasherProviderIdentifierTest")
    void hash_shouldReturnExpectedIdentifier(KeyedHasher hasher, Key key, AlgorithmIdentifier expected) throws Exception{
        byte[] message ="message".getBytes();
        AlgorithmIdentifier actual = hasher.hash(message, key).getIdentifier();

        Assertions.assertEquals(expected, actual, "hash method should return valid identification bytes");
    }

    @ParameterizedTest
    @MethodSource("hasherProviderIdentifierTest")
    void instance_shouldReturnExpectedIdentifier(KeyedHasher hasher, Key key, AlgorithmIdentifier expected) throws Exception {
        Assertions.assertEquals(expected, hasher.getIdentifier(), "instance should return valid identifier");
    }

    @ParameterizedTest
    @MethodSource("hasherProviderForString_message")
    void hash_shouldReturnExpectedHash(KeyedHasher hasher, Key key, byte[] expected) throws Exception {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        byte[] encoded =  hasher.hash(message,key).getEncoded();
        Assertions.assertArrayEquals(expected, encoded);
    }

    static Stream<Arguments> hasherProviderIdentifierTest() throws Exception{

        Key keySha224 = KeyGenerator.getInstance("HmacSHA224").generateKey();
        Key keySha256 = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Key keySha384 = KeyGenerator.getInstance("HmacSHA384").generateKey();
        Key keySha512 = KeyGenerator.getInstance("HmacSHA512").generateKey();

        return Stream.of(
          Arguments.of(HasherHMac.sha224(), keySha224, AlgorithmIdentifier.H_MAC_SHA224 ),
          Arguments.of(HasherHMac.sha256(), keySha256, AlgorithmIdentifier.H_MAC_SHA256 ),
          Arguments.of(HasherHMac.sha384(), keySha384, AlgorithmIdentifier.H_MAC_SHA384 ),
          Arguments.of(HasherHMac.sha512(), keySha512, AlgorithmIdentifier.H_MAC_SHA512 )
        );
    }

    //TODO simplify
    static Stream<Arguments> hasherProviderForString_message() throws Exception {

        Key keySha224 = createKey("lcTCk5OxM93ALOAQvrKl1T5yZAsdx1ZV0TlRHg==","HmacSHA224");
        byte[] expected224 = encode("6qNxBggCoCJekeko5a/AradfxoCtpuJjRTnbnQ==", AlgorithmIdentifier.H_MAC_SHA224);

        Key keySha256 = createKey("uObmNkIkn3FNZoP7VGOQltbvnIz/efPcJRZyzJ1C/Mk=","HmacSHA256");
        byte[] expected256 = encode("h/uPSznmRUX8aR3uzaON/ZUB6X1K72Kz/AZzpHXYbRE=", AlgorithmIdentifier.H_MAC_SHA256);

        Key keySha384 = createKey("BoJcAhYMWP8ZRj286rTIHN+lNjj9DIIwlgNEiCpS0fHvBkzK8xGuD9PS2Ypajtw3","HmacSHA384");
        byte[] expected384 = encode("GwI36IgnOkquwwslgtSbBz282tWMfezO9JFuOg88SDPjefB2joLcf11FeAxJWS+1", AlgorithmIdentifier.H_MAC_SHA384);

        Key keySha512 = createKey("FxfdZ5nLhfQdi2R2/LKbxWyc1srCEk4VWdAfHrwiGTIBKqz+t9+Hd7ElA8al93NZX/ceD/DCUqEF1fseNGeODQ==","HmacSHA512");
        byte[] expected512 = encode("15b90iL9L489NDdUplCPS2mS0feWr+1sdWB3XwBLiuln/k0DXoF6/LqlPiL7kULNFYX2nGGu+9ZTuBZRc+8uwA==", AlgorithmIdentifier.H_MAC_SHA512);

        return Stream.of(
                Arguments.of(HasherHMac.sha224(), keySha224, expected224),
                Arguments.of(HasherHMac.sha256(), keySha256, expected256),
                Arguments.of(HasherHMac.sha384(), keySha384, expected384),
                Arguments.of(HasherHMac.sha512(), keySha512, expected512)
        );
    }

    static Key createKey(String base64, String algorithm){
        byte[] key = Base64.getDecoder().decode(base64);
        return new SecretKeySpec(key, algorithm);
    }

    static byte[] encode(String base64, AlgorithmIdentifier identifier){
        byte[] pure = Base64.getDecoder().decode(base64);
        return ByteBuffer.allocate(2 + pure.length)
                .put(identifier.type())
                .put(identifier.variant())
                .put(pure)
                .array();
    }

}
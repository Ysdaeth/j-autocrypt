package dev.ysdaeth.autocrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AlgorithmIdentifierTest {

    @Test
    void constructor_shouldThrowException_onZeroByteType(){
        Assertions.assertThrows(
                IllegalArgumentException.class,
                ()-> new AlgorithmIdentifier((byte)0,(byte)1),
                "constructor should throw runtime exception on zero byte type"
        );
    }
    @Test
    void constructor_shouldThrowException_onZeroByteVariant(){
        Assertions.assertThrows(
                IllegalArgumentException.class,
                ()-> new AlgorithmIdentifier((byte)1, (byte)0),
                "constructor should throw runtime exception on zero byte type"
        );
    }

    @Test
    void type_shouldReturnType_whenConstructorWithArray(){
        byte[] encoded = new byte[]{1, 2, 3, 4};
        AlgorithmIdentifier identifier = new AlgorithmIdentifier(encoded);

        Assertions.assertEquals((byte)1, identifier.type(),
                "Type should return 1");
    }

    @Test
    void variant_shouldReturnVariant_whenConstructorWithArray(){
        byte[] encoded = new byte[]{1, 2, 3, 4};
        AlgorithmIdentifier identifier = new AlgorithmIdentifier(encoded);

        Assertions.assertEquals((byte)2, identifier.variant(),
                "variant should return 2");
    }

    @Test
    void bytes_shouldReturnIdentifierBytesWithTypeAndVariant(){
        AlgorithmIdentifier identifier = new AlgorithmIdentifier(new byte[]{1,2,3});
        byte[] expected = new byte[]{1,2};
        byte[] actual = identifier.bytes();

        Assertions.assertArrayEquals(expected, actual,
                "Should return byte array with bytes array [type, variant]");
    }

}
package dev.ysdaeth.autocrypt.hashing.authenticator.hmac;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

class HMacFactoryTest {

    @ParameterizedTest
    @MethodSource("hmacIdentifierProvider")
    void getInstance_shouldNotThrowException(AlgorithmIdentifier identifier) {
        Assertions.assertDoesNotThrow(
                ()->{
                    HMacFactory.getInstance(identifier);
                }
        );
    }

    @Test
    void getInstance_shouldThrowIdentifierException(){
        byte type = 0;
        while(++type != 0 ){
            if(type == AlgorithmIdentifier.H_MAC) continue;
            AlgorithmIdentifier identifier = new AlgorithmIdentifier(type,(byte)1);
            Assertions.assertThrowsExactly(AlgorithmIdentificationException.class,
                    ()-> HMacFactory.getInstance(identifier));
            type++;
        }
    }

    static Stream<AlgorithmIdentifier> hmacIdentifierProvider(){
        return Stream.of(
                AlgorithmIdentifier.H_MAC_SHA224,
                AlgorithmIdentifier.H_MAC_SHA256,
                AlgorithmIdentifier.H_MAC_SHA384,
                AlgorithmIdentifier.H_MAC_SHA512
        );
    }
}
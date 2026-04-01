package dev.ysdaeth.autocrypt.encryption.aes;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static dev.ysdaeth.autocrypt.AlgorithmIdentifier.*;

class AesFactoryTest {

    @Test
    void getInstance_shouldReturnProperInstance() throws Exception{
        Assertions.assertInstanceOf(AesGcm.class, AesFactory.getInstance(AES_GCM));
    }

    @Test
    void getInstance_shouldThrowException(){
        byte incorrectType = AES + 1;
        while(incorrectType != AES){
            if(incorrectType == 0) incorrectType++;
            AlgorithmIdentifier identifier = new AlgorithmIdentifier(incorrectType,(byte)1);
            Assertions.assertThrowsExactly(AlgorithmIdentificationException.class,
                    ()-> AesFactory.getInstance(identifier));
            incorrectType++;
        }
    }

}
package dev.ysdaeth.autocrypt;

/**
 * When there is not any known implementation of the algorithm specified by the {@link AlgorithmIdentifier}, i.e:
 * factory does not know type or variant of any matching algorithm implementation for that factory.
 */
public class AlgorithmIdentificationException extends Exception {
    public AlgorithmIdentificationException(String message) {
        super(message);
    }
}

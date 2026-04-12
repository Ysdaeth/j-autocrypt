package dev.ysdaeth.autocrypt;

/**
 * When there is not any known implementation of the algorithm specified by the {@link AlgorithmIdentifier}, i.e:
 * factory does not know type or variant of any matching algorithm implementation for that factory.
 */
public class AlgorithmIdentificationException extends Exception {
    /**
     * Creates checked exception, that should be thrown when algorithm identification failed, or is not recognized
     * @param message exception message
     */
    public AlgorithmIdentificationException(String message) {
        super(message);
    }
}

package dev.ysdaeth.autocrypt;

/**
 * Exception is thrown when Algorithm with specified identifier already exists in the registry
 */
public class AlgorithmRegistrationException extends RuntimeException {
    public AlgorithmRegistrationException(String message) {
        super(message);
    }
}

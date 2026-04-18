package dev.ysdaeth.autocrypt;

/**
 * Exception is thrown when algorithm with specified identifier already exists in the registry,
 * or other algorithm registration issue.
 */
public class AlgorithmRegistrationException extends RuntimeException {
    /**
     * Creates unchecked exception that should be thrown when algorithm registration failed due to
     * being already registered, or because of the other reason
     * @param message exception message
     */
    public AlgorithmRegistrationException(String message) {
        super(message);
    }
}

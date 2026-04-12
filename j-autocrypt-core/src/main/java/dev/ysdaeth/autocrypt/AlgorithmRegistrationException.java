package dev.ysdaeth.autocrypt;

/**
 * Exception is thrown when Algorithm with specified identifier already exists in the registry
 * or other related reason
 */
public class AlgorithmRegistrationException extends RuntimeException {
    /**
     * Creates unchecked exception that should be thrown when algorithm registration failed due to
     * being already registered, or other reason
     * @param message exception message
     */
    public AlgorithmRegistrationException(String message) {
        super(message);
    }
}

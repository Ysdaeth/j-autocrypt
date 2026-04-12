package dev.ysdaeth.autocrypt;

/**
 * Immutable Class representation of the algorithm identifier.
 * Algorithm identifier contains two bytes, where first byte is the algorithm identifier,
 * and the second byte is algorithm variant.
 * Byte value of 0x00 represents unknown, and must not be used as an algorithm type, or the
 * algorithm variant.
 * <p>Example</p>
 * Algorithm type: AES, Algorithm variant: GCM
 */
public class AlgorithmIdentifier {

    private final byte type;
    private final byte variant;

    /**
     * Creates algorithm identifier instance, where first identifier byte specifies the type
     * of the algorithm, and second byte specifies the algorithm variant.
     * When algorithm type or variant is set to 0x00, then {@link IllegalArgumentException} is thrown.
     * Constructor is available for flexibility, but static methods are encouraged to use.
     * @param type identifier byte of the algorithm
     * @param variant variant of the algorithm
     * @throws IllegalArgumentException wen algorithm type or variant is set to 0x00 byte
     */
    public AlgorithmIdentifier(byte type, byte variant) throws IllegalArgumentException {
        if(type == 0x00) throw new IllegalArgumentException(
                "Algorithm identifier variant must not be : " + type);

        if(variant == 0x00) throw new IllegalArgumentException(
                "Algorithm variant must not be 0 for this constructor");

        this.type = type;
        this.variant = variant;
    }

    /**
     * Resolves algorithm identifier based on the provided encoded bytes, where first byte
     * is the algorithm type and the second byte is the algorithm variant.
     * <blockquote><pre>
     *     Algorithm type: AES
     *     Algorithm variant: GCM
     * </pre></blockquote>
     * @param encoded identifier from the encoded bytes
     */
    public AlgorithmIdentifier(byte[] encoded){
        this(encoded[0],encoded[1]);
    }

    /**
     * Returns algorithm byte type like AES, Hmac, RSA, etc.
     * @return algorithm type byte
     */
    public byte type() {
        return type;
    }

    /**
     * Return algorithm byte variant like GCM, SHA256(for Hmac), OAEP, etc.
     * @return algorithm variant byte
     */
    public byte variant() {
        return variant;
    }

    @Override
    public boolean equals(Object other){
        if(other == null) return false;
        if(other instanceof AlgorithmIdentifier identifier){
            return identifier.type == type && identifier.variant == variant;
        }
        return false;
    }

    @Override
    public String toString(){
        return String.format("[type = %d, variant = %d]", type, variant);
    }
    @Override
    public int hashCode(){
        return type * 256 + variant;
    }
}

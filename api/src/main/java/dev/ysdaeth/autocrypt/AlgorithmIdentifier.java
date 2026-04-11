package dev.ysdaeth.autocrypt;

/**
 * Class representation of the algorithm identifier.
 * Algorithm identifier contains two bytes, where first is the algorithm identifier byte,
 * and the second is algorithm variant.
 * Byte value of 0x00, represents unknown, and must not be used as an algorithm type, or the
 * algorithm variant.
 * Public constructors are available, but static fields
 * like {@link AlgorithmIdentifier#AES_GCM} are encouraged to use.
 * <p>Example</p>
 * Algorithm type: AES, Algorithm variant: GCM == AlgorithmIdentifier.AES_GCM
 */
public class AlgorithmIdentifier {

    public static final byte AES = -128;
    public static final byte H_MAC = 1;

    public static final AlgorithmIdentifier AES_GCM = new AlgorithmIdentifier(AES,(byte)5);
    public static final AlgorithmIdentifier H_MAC_SHA224 = new AlgorithmIdentifier(H_MAC,(byte)1);
    public static final AlgorithmIdentifier H_MAC_SHA256 = new AlgorithmIdentifier(H_MAC,(byte)2);
    public static final AlgorithmIdentifier H_MAC_SHA384 = new AlgorithmIdentifier(H_MAC,(byte)3);
    public static final AlgorithmIdentifier H_MAC_SHA512 = new AlgorithmIdentifier(H_MAC,(byte)4);

    private final byte type;
    private final byte variant;

    /**
     * Creates algorithm identifier instance, where first identifier byte specifies type
     * of the algorithm, second byte specifies algorithm variant.
     * When algorithm type or variant is set to 0x00, then {@link IllegalArgumentException} is thrown.
     * Constructor is available for flexibility, but static methods are encouraged to use.
     * @param type identifier byte of the algorithm
     * @param variant variant of the algorithm
     * @throws IllegalArgumentException wen algorithm id or variant is 0x00 byte
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
     * Returns algorithm type like AES, Hmac, RSA, etc.
     * @return algorithm type
     */
    public byte type() {
        return type;
    }

    /**
     * return algorithm variant like GCM, SHA256(for Hmac), OAEP, etc.
     * @return algorithm variant
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

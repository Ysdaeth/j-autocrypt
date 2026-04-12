package dev.ysdaeth.autocrypt;

public class Identifiers {
    public static final AlgorithmIdentifier AES_GCM = new AlgorithmIdentifier((byte)0x01,(byte)0x06);
    public static final AlgorithmIdentifier H_MAC_SHA224 = new AlgorithmIdentifier((byte)0x80,(byte)0x03);
    public static final AlgorithmIdentifier H_MAC_SHA256 = new AlgorithmIdentifier((byte)0x80,(byte)0x04);
    public static final AlgorithmIdentifier H_MAC_SHA384 = new AlgorithmIdentifier((byte)0x80,(byte)0x05);
    public static final AlgorithmIdentifier H_MAC_SHA512 = new AlgorithmIdentifier((byte)0x80,(byte)0x06);
}

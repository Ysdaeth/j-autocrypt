package dev.ysdaeth.autocrypt;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Identifiers {
    public static final AlgorithmIdentifier UNKNOWN = new AlgorithmIdentifier((byte)0x7f,(byte)0x7f);

    public static final AlgorithmIdentifier AES_GCM = new AlgorithmIdentifier((byte)0x01,(byte)0x06);

    public static final AlgorithmIdentifier H_MAC_SHA224 = new AlgorithmIdentifier((byte)0x80,(byte)0x03);
    public static final AlgorithmIdentifier H_MAC_SHA256 = new AlgorithmIdentifier((byte)0x80,(byte)0x04);
    public static final AlgorithmIdentifier H_MAC_SHA384 = new AlgorithmIdentifier((byte)0x80,(byte)0x05);
    public static final AlgorithmIdentifier H_MAC_SHA512 = new AlgorithmIdentifier((byte)0x80,(byte)0x06);

    public static final AlgorithmIdentifier SHA224 = new AlgorithmIdentifier((byte)0x81,(byte)0x02);
    public static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier((byte)0x81,(byte)0x03);
    public static final AlgorithmIdentifier SHA384 = new AlgorithmIdentifier((byte)0x81,(byte)0x04);
    public static final AlgorithmIdentifier SHA512 = new AlgorithmIdentifier((byte)0x81,(byte)0x05);
    public static final AlgorithmIdentifier ARGON2D = new AlgorithmIdentifier((byte)0x82, (byte)0x01);
    public static final AlgorithmIdentifier ARGON2I = new AlgorithmIdentifier((byte)0x82, (byte)0x02);
    public static final AlgorithmIdentifier ARGON2ID = new AlgorithmIdentifier((byte)0x82, (byte)0x03);

    /**
     * Key or null when algorithm does not use key
     * @param identifier identifier
     * @return key or null
     * @throws Exception sometimes
     */
    public static SecretKey generateKey(AlgorithmIdentifier identifier) throws Exception{
        if(identifier.equals(H_MAC_SHA224)) return KeyGenerator.getInstance("HmacSHA224").generateKey();
        if(identifier.equals(H_MAC_SHA256)) return KeyGenerator.getInstance("HmacSHA256").generateKey();
        if(identifier.equals(H_MAC_SHA384)) return KeyGenerator.getInstance("HmacSHA384").generateKey();
        if(identifier.equals(H_MAC_SHA512)) return KeyGenerator.getInstance("HmacSHA512").generateKey();
        return null;
    }
}

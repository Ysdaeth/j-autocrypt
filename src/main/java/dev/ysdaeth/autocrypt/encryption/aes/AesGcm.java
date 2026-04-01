package dev.ysdaeth.autocrypt.encryption.aes;

import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.encryption.Encryptor;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;

class AesGcm extends Encryptor {

    private static final String cipherAlgorithm = "AES/GCM/NoPadding";
    private static final SecureRandom secureRandom = new SecureRandom();
    private final AlgorithmIdentifier identifier;

    AesGcm(AlgorithmIdentifier identifier){
        this.identifier = identifier;
    }

    /**
     * Encrypts data with aes gcm instance. Returns encoded bytes that contain:
     * <ul>
     *     <li> algorithm type (1 byte)</li>
     *     <li> algorithm variant (1 byte)</li>
     *     <li> initial vector length (1 byte)</li>
     *     <li> initial vector bytes (12 bytes)</li>
     *     <li> main encrypted bytes array (size based on input size)</li>
     * </ul>
     * Initial vector is made of 12 random bytes generated with {@link SecureRandom}
     * Throws Key exception when key does not match the algorithm instance {@link InvalidKeyException}
     * and {@link RuntimeException} when security provider could not provide cipher instance. Authentication tag
     * is set to 128 bits length.
     * @param raw raw data to encrypt.
     * @param key key for data encryption.
     * @return encoded bytes with metadata and encrypted byte array.
     * @throws KeyException when key does not match the algorithm instance,
     * i.e: key size, not initialized, etc
     */
    @Override
    public AlgorithmOutput encrypt(byte[] raw, Key key) throws KeyException, RuntimeException {
        GCMParameterSpec spec = generateGcmParams();
        Cipher cipher;
        byte[] output;
        try{
            cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE,key,spec);
            byte[] iv = spec.getIV();
            output = new byte[3 + iv.length + cipher.getOutputSize(raw.length)];
            output[0] = identifier.type();
            output[1] = identifier.variant();
            output[2] = (byte)iv.length;
            System.arraycopy(iv, 0, output, 3, iv.length);
            int outputDest = 3 + iv.length;
            cipher.doFinal(raw, 0, raw.length, output, outputDest);
        }catch (Exception e) {
            if(e instanceof InvalidKeyException) throw (KeyException) e;
            throw new RuntimeException(e.getMessage(),e);
        }
        return new AlgorithmOutput(output);
    }

    /**
     * Decrypts data from the encoded bytes array, which contains:
     * <ul>
     *     <li> algorithm type (1 byte)</li>
     *     <li> algorithm variant (1 byte)</li>
     *     <li> initial vector length (1 byte)</li>
     *     <li> initial vector bytes (12 bytes)</li>
     *     <li> main encrypted bytes array (size based on input size)</li>
     * </ul>
     * Throws Key exception when key does not match the algorithm instance {@link InvalidKeyException},
     * or provided key does not match encrypted data. Original exception {@link AEADBadTagException}
     * is transformed to KeyException
     * @param output output created by this algorithm instance
     * @param key key used for encryption
     * @return decrypted data
     * @throws KeyException when key does not match the encrypted data or cipher instance
     */
    @Override
    public byte[] decrypt(AlgorithmOutput output, Key key) throws KeyException {
        byte[] encoded = output.getEncoded();
        byte[] raw;
        try{
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            byte ivLen = encoded[2];
            byte[] iv = new byte[ivLen];

            // initial vector bytes array starts at index 3
            System.arraycopy(encoded, 3, iv, 0, ivLen);
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            int encryptedStart = 3 + ivLen;
            int encryptedLen = encoded.length -3 - ivLen;
            raw = new byte[encryptedLen - 128/8]; // -128 bits for tag length
            cipher.doFinal(encoded, encryptedStart, encryptedLen, raw, 0);
        }catch (Exception e){
            if(e instanceof AEADBadTagException) {
                throw new KeyException("Key does not match encrypted data." + e.getMessage(), e);
            }
            throw new RuntimeException(e.getMessage(),e);
        }
        return raw;
    }

    private static GCMParameterSpec generateGcmParams(){
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return new GCMParameterSpec(128,iv);
    }
}

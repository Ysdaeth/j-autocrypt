package dev.ysdaeth.autocrypt;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Encoded bytes order
 * <ol>
 *     <li>Algorithm type (byte)</li>
 *     <li>Algorithm variant (byte)</li>
 *     <li>Argon Type (byte)</li>
 *     <li>Argon version (byte)</li>
 *     <li>iterations (byte)</li>
 *     <li>parallelism (byte)</li>
 *     <li>salt length (byte)</li>
 *     <li>mem limit (integer, 4 bytes)</li>
 *     <li>salt (n bytes, from point 5)</li>
 *     <li>hash (n bytes)</li>
 * </ol>
 */
public class HasherArgon2 implements Hasher {

    private final SecureRandom random = new SecureRandom();

    private final Metadata ARGON_METADATA;
    private int hashLength;

    private HasherArgon2(Metadata metadata, int hashLength){
        ARGON_METADATA = metadata;
        this.hashLength = hashLength;
    }

    @Override
    public AlgorithmOutput hash(byte[] data) {
        byte[] salt = new byte[ARGON_METADATA.saltLength];
        random.nextBytes(salt);

        byte[] encoded = createEncoded(data, ARGON_METADATA, salt, hashLength);
        return new AlgorithmOutput(encoded);
    }

    private static byte[] createEncoded(byte[] data, Metadata metadata, byte[] salt, int hashLength){
        Argon2Parameters parameters = new Argon2Parameters.Builder(metadata.argonType)
                .withVersion(metadata.argonVersion)
                .withIterations(metadata.iterations)
                .withParallelism(metadata.parallelism)
                .withMemoryAsKB(metadata.memLimit)
                .withSalt(salt)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);

        // alg type, alg variant, argon type, argon version, iterations, parallelism, salt length(1 byte) = 7
        // memLimit int = 4
        int metadataLength = 7 + 4 + metadata.saltLength; // salt length i.e: 16 bytes
        byte[] encoded = ByteBuffer.allocate(metadataLength + hashLength)
                .put( metadata.identifier.type() )
                .put(metadata.identifier.variant())
                .put(metadata.argonType)
                .put(metadata.argonVersion)
                .put(metadata.iterations)
                .put(metadata.parallelism)
                .put(metadata.saltLength)
                .putInt(metadata.memLimit)
                .put(salt)
                .array();

        generator.generateBytes(data, encoded, metadataLength, hashLength);
        return encoded;
    }

    /**
     * Tests if raw data matches produced hash wrapped with {@link AlgorithmOutput}
     * @param data raw data to test
     * @param output hash to compare
     * @return true if matches, else false
     */
    @Override
    public boolean matches(byte[] data, AlgorithmOutput output) {
        byte[] encoded = output.getEncoded();
        Metadata metadata = Metadata.fromOutput(output);
        byte[] salt = new byte[metadata.saltLength];
        System.arraycopy(encoded, 11, salt, 0, metadata.saltLength);

        int hashStart = 11 + metadata.saltLength;
        int hashLength = encoded.length - hashStart;

        byte[] recalculated = createEncoded(data, metadata, salt, hashLength);

        return Arrays.equals(recalculated, hashStart, recalculated.length , encoded, hashStart, encoded.length);
    }

    @Override
    public AlgorithmIdentifier getIdentifier() {
        return ARGON_METADATA.identifier;
    }

    /**
     * Creates instance of Argon2id hasher with version 19.
     * @param identifier algorithm identifier
     * @param iterations argon iterations - value is cast to byte
     * @param parallelism argon parallelism - value is cast to byte
     * @param memKB RAM limit
     * @param hashLength hash length, which is not encoded bytes length but only hash length.
     *                   Encoded length is metadata bytes + hash bytes. This refers only to the hash length.
     * @return implementation Hasher with argon
     * @throws IllegalArgumentException when iterations or parallelism value is higher than {@link Byte#MAX_VALUE}
     */
    public static HasherArgon2 argon2id(AlgorithmIdentifier identifier, int iterations, int parallelism,
                                        int memKB, int hashLength) throws IllegalArgumentException{

        if(iterations > Byte.MAX_VALUE) throw new IllegalArgumentException(
                "Iterations value must not be higher than:"+ Byte.MAX_VALUE);

        if(parallelism > Byte.MAX_VALUE) throw new IllegalArgumentException(
                "Parallelism value must not be higher than: "+ Byte.MAX_VALUE);

        Metadata metadata = new Metadata();
        metadata.identifier = identifier;
        metadata.argonType = Argon2Parameters.ARGON2_id;
        metadata.argonVersion = Argon2Parameters.ARGON2_VERSION_13;
        metadata.iterations = (byte) iterations;
        metadata.parallelism = (byte) parallelism;
        metadata.saltLength = 16;
        metadata.memLimit = memKB;
        return new HasherArgon2(metadata, hashLength);
    }

    private static final class Metadata {
        AlgorithmIdentifier identifier; // 0, 1 index
        byte argonType; // 2 index
        byte argonVersion; // 3 index
        byte iterations; // 4 index
        byte parallelism; // 5 index
        byte saltLength; // 6 index
        int memLimit; // 7, 8, 9, 10 index
        // salt from 11 index to 11 + saltLength

        private static Metadata fromOutput(AlgorithmOutput output){
            byte[] encoded = output.getEncoded();
            Metadata metadata = new Metadata();
            metadata.identifier = output.getIdentifier();
            metadata.argonType = encoded[2];
            metadata.argonVersion = encoded[3];
            metadata.iterations = encoded[4];
            metadata.parallelism = encoded[5];
            metadata.saltLength = encoded[6];
            metadata.memLimit = ByteBuffer.wrap(encoded, 7, 4).getInt();
            return metadata;
        }
    }

}

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

    private final AlgorithmIdentifier identifier;
    private final ArgonMetadata ARGON_METADATA;
    private final int hashLength;

    private HasherArgon2(AlgorithmIdentifier identifier, ArgonMetadata metadata, int hashLength){
        ARGON_METADATA = metadata;
        this.hashLength = hashLength;
        this.identifier = identifier;
    }

    @Override
    public AlgorithmOutput hash(byte[] data) {
        byte[] salt = new byte[ARGON_METADATA.saltLength];
        random.nextBytes(salt);

        byte[] encoded = createEncoded(data, ARGON_METADATA, salt, hashLength);
        return new AlgorithmOutput(encoded);
    }

    private byte[] createEncoded(byte[] data, ArgonMetadata metadata, byte[] salt, int hashLength){
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
                .put(identifier.type() )
                .put(identifier.variant())
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
        ArgonMetadata metadata = validateOutput(output);
        if(metadata == null) return false;
        byte[] encoded = output.getEncoded();
        byte[] salt = new byte[metadata.saltLength];
        System.arraycopy(encoded, 11, salt, 0, metadata.saltLength);

        int hashStart = 11 + metadata.saltLength;
        int hashLength = encoded.length - hashStart;
        byte[] recalculated = createEncoded(data, metadata, salt, hashLength);

        return Arrays.equals(recalculated, hashStart, recalculated.length , encoded, hashStart, encoded.length);
    }


    @Override
    public AlgorithmIdentifier getIdentifier() {
        return identifier;
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
                                       int memKB, int hashLength) throws IllegalArgumentException {

        return createArgon(identifier,
                Argon2Parameters.ARGON2_id, Argon2Parameters.ARGON2_VERSION_13,
                iterations, parallelism, memKB, hashLength);
    }

    /**
     * Creates instance of Argon2i hasher with version 19.
     * @param identifier algorithm identifier
     * @param iterations argon iterations - value is cast to byte
     * @param parallelism argon parallelism - value is cast to byte
     * @param memKB RAM limit
     * @param hashLength hash length, which is not encoded bytes length but only hash length.
     *                   Encoded length is metadata bytes + hash bytes. This refers only to the hash length.
     * @return implementation Hasher with argon
     * @throws IllegalArgumentException when iterations or parallelism value is higher than {@link Byte#MAX_VALUE}
     */
    public static HasherArgon2 argon2i(AlgorithmIdentifier identifier, int iterations, int parallelism,
                                        int memKB, int hashLength) throws IllegalArgumentException {
        return createArgon(identifier,
                Argon2Parameters.ARGON2_i, Argon2Parameters.ARGON2_VERSION_13,
                iterations, parallelism, memKB, hashLength);
    }

    /**
     * Creates instance of Argon2d hasher with version 19.
     * @param identifier algorithm identifier
     * @param iterations argon iterations - value is cast to byte
     * @param parallelism argon parallelism - value is cast to byte
     * @param memKB RAM limit
     * @param hashLength hash length, which is not encoded bytes length but only hash length.
     *                   Encoded length is metadata bytes + hash bytes. This refers only to the hash length.
     * @return implementation Hasher with argon
     * @throws IllegalArgumentException when iterations or parallelism value is higher than {@link Byte#MAX_VALUE}
     */
    public static HasherArgon2 argon2d(AlgorithmIdentifier identifier, int iterations, int parallelism,
                                        int memKB, int hashLength) throws IllegalArgumentException {
        return createArgon(identifier,
                Argon2Parameters.ARGON2_d, Argon2Parameters.ARGON2_VERSION_13,
                iterations, parallelism, memKB, hashLength);
    }

    public static HasherArgon2 createArgon(AlgorithmIdentifier identifier,int type, int version, int iterations,
                                           int parallelism, int memKB, int hashLength) throws IllegalArgumentException {

        if(iterations > Byte.MAX_VALUE) throw new IllegalArgumentException(
                "Iterations value must not be higher than:"+ Byte.MAX_VALUE);

        if(parallelism > Byte.MAX_VALUE) throw new IllegalArgumentException(
                "Parallelism value must not be higher than: "+ Byte.MAX_VALUE);

        ArgonMetadata metadata = initMetadata(iterations, parallelism, memKB);
        metadata.argonType = (byte)type;
        metadata.argonVersion = (byte)version;
        return new HasherArgon2(identifier, metadata, hashLength);

    }

    private static ArgonMetadata initMetadata(int iterations, int parallelism, int memKB){
        ArgonMetadata metadata = new ArgonMetadata();
        metadata.iterations = (byte) iterations;
        metadata.parallelism = (byte) parallelism;
        metadata.saltLength = 16;
        metadata.memLimit = memKB;
        return metadata;
    }
    private ArgonMetadata validateOutput(AlgorithmOutput output){
        if(!output.getIdentifier().equals(identifier)) return null;
        byte[] encoded = output.getEncoded();
        if(encoded.length < ArgonMetadata.MIN_SIZE) return null;
        ArgonMetadata metadata = ArgonMetadata.fromOutput(output);
        int minWithSalt = ArgonMetadata.MIN_SIZE + metadata.saltLength;
        if(minWithSalt > encoded.length) return null;
        return metadata;
    }

    private static final class ArgonMetadata {
        private static final int MIN_SIZE = 11;

        byte argonType; // 2 index
        byte argonVersion; // 3 index
        byte iterations; // 4 index
        byte parallelism; // 5 index
        byte saltLength; // 6 index
        int memLimit; // 7, 8, 9, 10 index

        private ArgonMetadata(){}

        private static ArgonMetadata fromOutput(AlgorithmOutput output){
            byte[] encoded = output.getEncoded();

            ArgonMetadata metadata = new ArgonMetadata();
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

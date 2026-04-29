package dev.ysdaeth.autocrypt;

import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;

public class HasherArgon2 implements Hasher {

    private final AlgorithmIdentifier identifier;

    private int iterations;
    private int memLimit;
    private int hashLength;
    private int parallelism;
    private int argonType; // 0=d, 1=i, 2=id

    private HasherArgon2(AlgorithmIdentifier identifier, int iterations,
                         int memLimit, int parallelism, int hashLength,
                         int argonType){
        this.identifier = identifier;
        this.iterations = iterations;
        this.memLimit = memLimit;
        this.parallelism = parallelism;
        this.hashLength = hashLength;

        throw new RuntimeException("Not implemented");
    }

    private final SecureRandom random = new SecureRandom();

    @Override
    public AlgorithmOutput hash(byte[] data) {
        Argon2Parameters parameters = createParams();
        throw new RuntimeException("Not implemented");
    }

    @Override
    public boolean matches(byte[] data, AlgorithmOutput output) {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public AlgorithmIdentifier getIdentifier() {
        return identifier;
    }

    private byte[] generateSalt(int length){
        byte[] salt = new byte[length];
        random.nextBytes(salt);
        return salt;
    }

    private Argon2Parameters createParams(){
        byte[] salt = generateSalt(16);
        return new Argon2Parameters.Builder(argonType)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memLimit)
                .withParallelism(parallelism)
                .withSalt(salt).build();
    }

    private static class BytesEncoder {
        byte type;
        byte variant;
        byte iterations;
        byte parallelism;
        int memLimit;
        byte saltLength;
        byte[] salt;
        byte[] hash;

        private BytesEncoder(AlgorithmOutput output){
            throw new RuntimeException("Not implemented");
        }

        private AlgorithmOutput encode(){
            throw new RuntimeException("Not implemented");
        }
        /*
         CORE:
         algorithm type(1),
         algorithm variant(1)
          =============== 2bytes
         */

        /*
         METADATA:
         iterations(1)
         parallelism(1)
         memLimit(4)
         saltLen(1)
         salt(n)
         =============== 7bytes + salt.length
        */

        // CORE + METADATA + HASH
    }
}

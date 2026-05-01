# Hasher
`API MODULE`

Role of the hasher is data hashing. It follows the [AlgorithmOutput](AlgorithmOutput.md)
pattern to automate algorithm selection based on the identification bytes, and to store
all necessary metadata that allows data hash recalculation to test if matches.

```java
public interface Hasher extends Cryptographic {
    AlgorithmOutput hash(byte[] data);
    boolean matches(byte[] data, AlgorithmOutput output);
}
```

Extends [Cryptographic](Cryptographic.md) interface to make it possible for Hasher implementations
to be grouped and return it's [AlgorithmIdentifier](AlgorithmIdentifier.md)
# KeyedHasher
`API MODULE`

Role of the keyed hasher is data hashing with a cryptographic key. It follows the [AlgorithmOutput](AlgorithmOutput.md) 
pattern to automate algorithm selection based on the identification bytes, and to store
all necessary metadata that allows data hash recalculation to test if matches.

```java
public interface KeyedHasher extends Cryptographic {
    AlgorithmOutput hash(byte[] data, Key key) throws KeyException;
    boolean matches(byte[] data, AlgorithmOutput output, Key key) throws KeyException;
}
```

Extends [Cryptographic](Cryptographic.md) interface to make it possible for Hasher implementations
to be grouped and return it's [AlgorithmIdentifier](AlgorithmIdentifier.md)
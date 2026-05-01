# Encryptor
`API MODULE` 

Role of the encryptor is data encryption with a cryptographic key. It follows the [AlgorithmOutput](AlgorithmOutput.md)
pattern to automate algorithm selection based on the identification bytes, and to store
all necessary metadata that allows data decryption.

```java
public interface Encryptor extends Cryptographic {
    AlgorithmOutput encrypt(byte[] raw, Key key) throws KeyException;
    byte[] decrypt(AlgorithmOutput encoded, Key key) throws KeyException;
}
```

Extends [Cryptographic](Cryptographic.md) interface to make it possible for Hasher implementations
to be grouped and return it's [AlgorithmIdentifier](AlgorithmIdentifier.md)
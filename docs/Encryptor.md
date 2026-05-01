# Encryptor
`API MODULE` 

Role of the encryptor is data encryption with a secret key. It follows the [AlgorithmIdentifier](AlgorithmIdentifier.md) 
to ease algorithm identification and automate algorithm selection based on the identification bytes and to store 
all necessary metadata to decrypt encrypted data.

```java
public interface Encryptor extends Cryptographic {
    AlgorithmOutput encrypt(byte[] raw, Key key) throws KeyException;
    byte[] decrypt(AlgorithmOutput encoded, Key key) throws KeyException;
}
```

Encryptor extends [Cryptographic](Cryptographic.md) interface to make it possible for Encryptor implementations
to be grouped and return it's [AlgorithmIdentifier](AlgorithmIdentifier.md)
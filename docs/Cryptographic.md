# Cryptographic
`API MODUE`

Cryptographic interface is a mark interface to group Cryptographic algorithms
like [Hasher](Hasher.md), [KeyedHasher](KeyedHasher.md), [Encryptor](Encryptor.md) or any other
cryptographic interfaces.

It has one method, that is common for all cryptographic implementations, which returns the algorithm instance identifier.   
```java
AlgorithmIdentifier getIdentifier();
```
*See* [AlgorithmIdentifier](AlgorithmIdentifier.md)
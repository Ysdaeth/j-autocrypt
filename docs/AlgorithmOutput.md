# AlgorithmOutput
`API MODULE`

Algorithm output is a class wrapper for output of the algorithms. It contains 
[algorithm identifier](AlgorithmIdentifier.md) bytes, optional metadata bytes if algorithm uses metadata like 
initial vector, salt, iterations, etc. Last part is array of the main bytes which may be hash or encrypted bytes 
produced by the algorithm instance. 

---

Encoded bytes should be in the following order

- Algorithm type byte
- Algorithm variant byte
- Optional metadata bytes
- Main bytes (hash or encrypted)

Interfaces that return AlgorithmOutput are

- [Hasher](Hasher.md)
- [KeyedHasher](KeyedHasher.md)
- [Encryptor](Encryptor.md)
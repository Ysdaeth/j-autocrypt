# CryptographicRegistry 
`core module`   

Cryptographic registry is a class that stores and provides implementation of the
cryptographic algorithms like [KeyedHasher](KeyedHasher.md),  [Hasher](Hasher.md), [Encryptor](Encryptor.md) or any other
interface that extends [Cryptographic](Cryptographic.md) interface.

## How it works
Let's say that we have a class
```java
public class MyHasher implements Hasher { ... }
```

As we can see, a class implements Hasher interface. Now let's take a look at the [Hasher](Hasher.md) interface.
```java
public interface Hasher extends Cryptographic { ... }
```
Hasher interface extends [Cryptographic](Cryptographic.md) interface. Cryptographic interface acts as a 
mark interface to gather all cryptographic implementations like: [KeyedHasher](KeyedHasher.md), 
[Hasher](Hasher.md) or [Encryptor](Encryptor.md) - they all extends Cryptographic interface.

### Create registry
To create registry of Hasher type, we can call `of` method uses varargs, that mean you can pass as 
many instances as JVM allows.

```java
CryptographicRegistry<Hasher> hasherRegistry = CryptographicRegistry.of(
        new MyHasher1(), new MyHasher2(), new MyHasher3()
);
```

Other way to create registry is to pass suppliers
```java
CryptographicRegistry<Hasher> hasherRegistry = CryptographicRegistry.of(
        ()->new MyHasher1(), ()->new MyHasher2(), ()->new MyHasher3()
);
```
It is also possible to call a method, that receives single Cryptographic object.
```java
hasherRegistry.register( new MyHasher() );
hasherRegistry.register( ()-> new MyHasher() );
```

#### What is the difference
Difference is that when we use instance, the same instance is being used for every encryption, hashing, etc. 
It is useful, when we don't want to create a new instance every time, when cryptographic operation is performed,
for instance, when constructor is heavy. Suppliers are useful when implementation needs to be initialized everytime
before any cryptographic operation.

### Get registered
One thing that was skipped to simplify, is importance of the [AlgorithmIdentifier](IDENTIFIERS.md) class. 
Every Cryptographic algorithm must have an identification bytes, those bytes may be any bytes you like (expect 0x00 bytes),
but I use these [identifiers](IDENTIFIERS.md).

Every Cryptographic class must return its identifier.
```java
public interface Cryptographic {
    AlgorithmIdentifier getIdentifier();
}
```
So let's assume that class `MyHasher` uses bytes `0x01` and `0x02` - which integer representation is just `1` and `2`.

Let's find our Hasher
```java
byte type = 0x01;
byte variant = 0x02;
AlgorithmIdentifier myHasherId = new AlgorithmIdentifier(type, variant);

Hasher myHasher = hasherRegistry.getRegistered(myHasherId);
```
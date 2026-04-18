# j-autocrypt
Encryption and hashing library for dynamic algorithm resolution, 
eliminating the need of storing the algorithm metadata for decryption and hash comparison.

> [!NOTE]
> GitHub and Maven packages are not available, to use the library, clone the repository and install dependencies locally.
> Packages downloads will be available after Jun 2026

Main
- [How to use](#how-to-use)
- [Bytes encoding](#bytes-encoding)
- [TODO list](#target-list)
- [Requirements](#requirements)

API
- [API MODULE](#api-module)
    - [AlgorithmIdentifier](#algorithmidentifierclass)
    - [AlgorithmOutput](#algorithmoutputclass)
    - [Encryptor](#encryptorclass)
    - [KeyedHasher](#keyedhasherclass)
    - [Hasher](#hasherclass)

Core
- [CORE MODULE](#core-module)
    - [HashingManager](#hashingmanagerclass)
    - [EncryptionManager](#encryptionmanagerclass)
    - [CryptographicRegistry](#cryptograhpicregistryclass)

API Implementations
- Encryption  
  [AES GCM](#encryptoraesgcmclass)
- Hashing  
[H Mac](#hasherhmacclass), [SHA](#hashershaclass)

## Bytes encoding
Encoded bytes are bytes produced by the algorithm and are wrapped with the [AlgorithmOutput](#algorithmoutputclass).
Encoded bytes are in the following order:
- Algorithm type (1 byte) i.e: AES.
- Algorithm variant (1byte) i.e: GCM
- Metadata bytes (Optional) i.e: metadata length, initial vector, salt, etc.
- Main algorithm bytes (hash or encrypted bytes produced by the implementation)  

Metadata bytes are optional and their presence depends on the algorithm implementation.

## How to use
We will focus on the Encryption part, but hashing part is very similar.

### Project object model 
First, lets install the [core](#core-module) package and one of the [Encryptors](#encryptorclass) implementations. 
In this case we will use [AES GCM](#encryptoraesgcmclass), but you can create your own implementation or 
install other dependency.
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-core</artifactId>
    <version>0.1</version>
</dependency>

<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-aes-gcm</artifactId>
    <version>0.1</version>
</dependency>
```

---
### Register Encryptor
Now, lets create [Cryptographic registry](#cryptograhpicregistryclass) and register the AES GCM encryptor. Register method
accepts the Supplier<[Encryptor](#encryptorclass)>, but to keep example simple, we will pass instance reference to the object 
and make the registry to wrap it with the supplier internally.   
We can define own [identifier](#algorithmidentifierclass) that will be used by the encryptor.

```java
AlgorithmIdentifier identifierAesGcm = new AlgorithmIdentifier( (byte) 0x01, (byte) 0x06 );
Encryptor aes = new EncryptorAesGcm(identifier);

CryptographicRegistry<Encryptor> registry = new CryptographicRegistry<>();
registry.register(aes);
```
> [!TIP]
> Algorithm identifier first byte should be the algorithm type, second byte the algorithm variant.
> You can create own identifiers, but take a look at [Proposed identifiers](docs/IDENTIFIERS.md)

---
### Encryption Manager - encryption
We already have the EncryptorRegistry, now we can inject it into the 
[EncryptionManager](#encryptionmanagerclass). When encrypting, we need to specify the algorithm we want to 
use - we've already created it before. 
Encoded bytes contain identifier, metadata and encrypted bytes. We will take an advantage of it later.

```java
EncryptionManager manager = new EncryptionManager(registry);

byte[] secret = "secret".getBytes();
Key secretKey = KeyGenerator.getInstance("AES").generateKey();

AlgorithmOutput output = manager.encrypt(secret, secretKey, identifierAesGcm);

byte[] encodedBytes = output.getEncoded();
```

---
### Encryption Manager - decryption
Finally, when we want to decrypt our data we can use `encodedBytes` to provide decryptor. 
Here we wrap the encoded bytes with the [AlgorithmOutput](#algorithmoutputclass). Encoded bytes must follow rules of the [Bytes encoding](#bytes-encoding)
```java
AlgorithmOutput output = new AlgorithmOutput( encodedBytes );
byte[] decrypted = manager.decrypt(output, secretKey);
```
> [!NOTE]  
> In this example we don't need to specify the AlgorithmIdentifier because it is already computed in our encoded bytes 

---

## API MODULE
Api module contains interfaces for the 3rd party applications or
libraries that extend this library. It allows to extend hashing and encryption algorithms pool used by
the [EncryptionManager](#encryptionmanagerclass) and [HashingManager](#hashingmanagerclass) from the [Core module](#core-module)  
*Install API package with maven*
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-api</artifactId>
    <version>0.1</version>
</dependency>
```
### AlgorithmIdentifier.class
Algorithm identifier represents the bytes pair to identify the algorithm instance.
First byte is meant to represent the algorithm type, for example 'AES'. 
Second byte is meant to represent the algorithm variant like 'GCM'.

---
### AlgorithmOutput.class
Algorithm output is a wrapper for the [encoded bytes](#bytes-encoding).

---
### Encryptor.class
Interface for encryptors that create [AlgorithmOutput](#algorithmoutputclass). 
It allows to create encrypted data and store all non-secret metadata 
required for decryption (initial vector, etc.) and encrypted bytes.

---
### KeyedHasher.class
Interface for hashers that uses secret keys to create [AlgorithmOutput](#algorithmoutputclass).
It allows to create hash of the data, which should store all non-secret metadata 
(salt, iterations, etc.) and hash itself.

---

### Hasher.class
Interface for the instances, which create [AlgorithmOutput](#algorithmoutputclass).
It allows to create hash of the data, which should store all non-secret metadata 
(salt, etc.) and hash itself.

---

## CORE MODULE
Core module contains the core functionality of the library. These components
are responsible for dynamic selection of the cryptographic algorithm implementations to produce 
[AlgorithmOutput](#algorithmoutputclass).  
When performing encryption or hashing, you must provide the [AlgorithmIdentifier](#algorithmoutputclass) and data to perform
cryptographic operation with selected algorithm.   
For decryption or hash verification the algorithm identifier is resolved from the encoded bytes, and proper 
algorithm implementation is provided automatically.  
*Install the CORE package with maven:*
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-core</artifactId>
    <version>0.1</version>
</dependency>
```
### HashingManager.class
Is responsible for data hashing based on the selected [AlgorithmIdentifier](#algorithmidentifierclass) and automatic
algorithm implementation selection for the hash verification based on the [bytes encoding](#bytes-encoding)

---
### KeyedHasherRegistry.class
Keyed hasher registry stores instances of the [KeyedHasher](#keyedhasherclass).
It is wrapper class for the Map< [AlgorithmIdentifier](#algorithmidentifierclass), [KeyedHasher](#keyedhasherclass) >

---
### EncryptionManager.class
It is responsible for data encryption based on the selected [AlgorithmIdentifier](#algorithmidentifierclass) and
automatic algorithm implementation selection for data decryption based on the [bytes encoding](#bytes-encoding)

---
### CryptograhpicRegistry.class
Registry to store cryptographic algorithms that implements [Encryptor](#encryptorclass), [KeyedHasher](#keyedhasherclass), 
and [Hasher](#hasherclass). Every algorithm implementation is assigned to the unique identifier.

---

## Implementation modules
Implementation modules contain implementation for the [Encryptor](#encryptorclass) or [KeyedHasher](#keyedhasherclass) 
from the [API MODULE](#api-module) to extend functionality of the [HashingManager](#hashingmanagerclass) or 
[EncryptionManager](#encryptionmanagerclass) from the [CORE MODULE](#core-module) 

### EncryptorAesGcm.class
[Encryptor](#encryptorclass)  
128bit authentication tag and 96bit initial vector with SecureRandom. Cipher instance provided by the `Java Security Provider`.  
*Install package with maven:*
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-aes-gcm</artifactId>
    <version>0.1</version>
</dependency>
```
> [!WARNING]
> Collision chance for random 96bit initial vector is low, but not zero. Remember about the key rotations.

---
### HasherHMac.class
[KeyedHasher](#keyedhasherclass)  
HMac with SHA224, SHA256, SHA384 and SHA512.
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-h-mac-sha</artifactId>
    <version>0.1</version>
</dependency>
```
---
### HasherSha.class
[Hasher](#hasherclass)  
SHA224, SHA256, SHA384, SHA512
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-sha</artifactId>
    <version>0.1</version>
</dependency>
```

## Requirements
- Java 25
- Designed for OpenJDK

## Target list
- [x] AES GCM
- [x] HMac Sha 224
- [x] HMac Sha 256
- [x] HMac Sha 384
- [x] HMac Sha 512
- [x] Sha 224
- [x] Sha 256
- [x] Sha 384
- [x] Sha 512
- [ ] Bcrypt
- [ ] RSA OAEP
  
New target list will be released after this one is completed
# j-autocrypt
Encryption and hashing library to automatically handle algorithm resolution, 
eliminating the need to store algorithm metadata for decryption and hash comparison.

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

Core
- [CORE MODULE](#core-module)
    - [HashingManager](#hashingmanagerclass)
    - [KeyedHasherRegistry](#keyedhasherregistryclass)
    - [EncryptionManager](#encryptionmanagerclass)
    - [EncryptorRegistry](#encryptorregistryclass)

API Implementations
- Encryption  
  [AES GCM](#encryptoraesgcmclass)
- Hashing  
[H Mac](#hasherhmacclass)

## Bytes encoding
Encoded bytes are bytes produced by the algorithm and are wrapped by the [AlgorithmOutput](#algorithmoutputclass) class object.
Encoded bytes are in the following order:
- Algorithm type (1 byte) i.e: AES.
- Algorithm variant (1byte) i.e: GCM
- Metadata bytes (Optional) i.e: metadata length, initial vector, salt, etc.
- Main algorithm bytes (hash or encrypted bytes produced by the implementation)
Metadata bytes are optional and their presence depends on the algorithm implementation.

## How to use
We will focus on the Encryption part, but hashing part is almost the same.

### Project object model 
First, lets install [core](#core-module) package and one of the [Encryptor](#encryptorclass) implementations, 
in this case we will use [AES GCM](#encryptoraesgcmclass), but you can create your own implementation or 
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
Now, lets create [EncryptorRegistry](#encryptorregistryclass) and register AES GCM. Registry method
accepts Supplier<[Encryptor](#encryptorclass)>, but to keep example simple, we will pass instance reference to the object 
and make the registry to wrap it with the supplier internally.   
We can define own [identifier](#algorithmidentifierclass) that will be used by the encryptor.

```java
AlgorithmIdentifier identifierAesGcm = new AlgorithmIdentifier( (byte) 0x01, (byte)0x06 );
Encryptor aes = new EncryptorAesGcm(identifier);
EncryptorRegistry registry = new EncryptorRegistry();
registry.register(aes);
```
> [!TIP]
> Algorithm identifier first byte should be the algorithm type, second byte the algorithm variant.
> You can create own identifiers, but take a look at [Proposed identifiers](docs/IDENTIFIERS.md)

---
### Encryption Manager - encryption
We already have the EncryptorRegistry, now we can inject it into 
[EncryptionManager](#encryptionmanagerclass). When encrypting we need to create or use static 
[AlgorithmIdentifier](#algorithmidentifierclass) to specify which algorithm we want to use.

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
Here we wrap encoded bytes with [AlgorithmOutput](#algorithmoutputclass). Encoded bytes must follow rules of the [Bytes encoding](#bytes-encoding)
```java
AlgorithmOutput output = new AlgorithmOutput( encodedBytes );
byte[] decrypted = manager.decrypt(output, secretKey);
```
> [!NOTE]  
> In this example we don't need to specify the AlgorithmIdentifier because it is already computed in our encrypted secret 

---

## API MODULE
Api module contains interfaces for the 3rd party applications or
libraries associated with this library. It allows to extend hashing and encryption algorithms range used by
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
First byte is for algorithm type, for example 'AES', and second byte is algorithm variant like 'GCM'.

---
### AlgorithmOutput.class
Algorithm output is a wrapper for the [encoded bytes](#bytes-encoding) created by the algorithm.

---
### Encryptor.class
Interface for the instances, which create [AlgorithmOutput](#algorithmoutputclass) with secret key. 
It allows to create encrypted data and store all non-secret metadata required for decryption (initial vector, etc.),
and encrypted bytes.

---
### KeyedHasher.class
Interface for the instances, which create [AlgorithmOutput](#algorithmoutputclass) with secret key.
It allows to create hash of the data, which should store all non-secret metadata for hash comparison (salt, etc.), 
and hash itself.

---

### Hasher.class
Interface for the instances, which create [AlgorithmOutput](#algorithmoutputclass).
It allows to create hash of the data, which should store all non-secret metadata for hash comparison (salt, etc.),
and hash itself.

---

## CORE MODULE
Core module contains hashing and encryption managers which are core of the library. These components
are responsible for dynamic selection of the cryptographic algorithm implementations to produce 
[AlgorithmOutput](#algorithmoutputclass).  
When performing encryption or hashing, you must provide the [AlgorithmIdentifier](#algorithmoutputclass) and data to perform
cryptographic operation.   
For decryption or hash verification the algorithm identifier is resolved from the encoded bytes, and proper 
algorithm implementation is provided.  
*Install CORE package with maven:*
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
### EncryptorRegistry.class
Encryptor registry stores instances of the [Encryptor](#encryptorclass). 
It is wrapper class for Map<[AlgorithmIdentifier](#algorithmidentifierclass),[Encryptor](#encryptorclass)>

---

## Implementation modules
Implementation modules contain implementation for the [Encryptor](#encryptorclass) or [KeyedHasher](#keyedhasherclass) 
from the [API MODULE](#api-module) to extend functionality of the [HashingManager](#hashingmanagerclass) or 
[EncryptionManager](#encryptionmanagerclass) from the [CORE MODULE](#core-module) 

### EncryptorAesGcm.class
128bit authentication tag and 96bit initial vector with SecureRandom.Cipher instance provided by the `Java Security Provider`.  
*Install package with maven:*
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-aes-gcm</artifactId>
    <version>0.1</version>
</dependency>
```
> [!WARNING]
> Collision chance for random 96bit initial vector is low, but not zero. Remember about the key rotation.

---
### HasherHMac.class
With SHA224, SHA256, SHA384, SHA512 accessible with static getter method
```xml
<dependency>
    <groupId>dev.ysdaeth.autocrypt</groupId>
    <artifactId>j-autocrypt-h-mac-sha</artifactId>
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
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
- [API MODULE](docs/api/0.Api.md)
    - [AlgorithmIdentifier](docs/api/1.AlgorithmIdentifier.md)
    - [AlgorithmOutput](docs/api/2.AlgorithmOutput.md)
    - [Cryptographic](docs/api/3.Cryptographic.md)
    - [Encryptor](docs/api/4.Encryptor.md)
    - [Hasher](docs/api/5.Hasher.md)
    - [KeyedHasher](docs/api/6.KeyedHasher.md)

Core
- [CORE MODULE](docs/core/0.Core.md)
    - [CryptographicRegistry](docs/core/1.CryptographicRegistry.md)
    - [EncryptionManager](docs/core/2.EncryptionManager.md)
    - [HashingManager](docs/core/3.HashingManager.md)

[API Implementations](docs/implementations/0.Implementations.md)
- Encryption  
  [AES GCM](docs/implementations/1.EncryptorAesGcm.md)


- Hashing  
  [H Mac](docs/implementations/2.HasherHMac.md), [SHA](docs/implementations/3.HasherSHA.md), [Argon2](docs/implementations/3.HasherArgon2.md)

## Bytes encoding
Encoded bytes are bytes produced by the algorithm and are wrapped with the [AlgorithmOutput](docs/api/2.AlgorithmOutput.md).
Encoded bytes are in the following order:
- Algorithm type (1 byte) i.e: AES.
- Algorithm variant (1byte) i.e: GCM
- Metadata bytes (Optional) i.e: metadata length, initial vector, salt, etc.
- Main algorithm bytes (hash or encrypted bytes produced by the implementation)  

Metadata bytes are optional and their presence depends on the algorithm implementation.

## How to use
We will focus on the Encryption part, but hashing part is very similar.

### Project object model 
First, lets install the [core](docs/core/0.Core.md) package and one of the [Encryptors](docs/api/4.Encryptor.md) implementation. 
In this case we will use [AES GCM](docs/implementations/1.EncryptorAesGcm.md), but you can create your own implementation or 
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
Now, lets create [Cryptographic registry](docs/core/1.CryptographicRegistry.md) and register the AES GCM encryptor. Register method
accepts the Supplier<[Encryptor](docs/api/4.Encryptor.md)>, but to keep example simple, we will pass instance reference to the object 
and make the registry to wrap it with the supplier internally.   
We can define own [identifier](docs/api/1.AlgorithmIdentifier.md) that will be used by the encryptor.

```java
AlgorithmIdentifier identifierAesGcm = new AlgorithmIdentifier( (byte) 0x01, (byte) 0x06 );
Encryptor aes = new EncryptorAesGcm(identifier);

CryptographicRegistry<Encryptor> registry = new CryptographicRegistry<>();
registry.register(aes);
```
> [!TIP]
> Algorithm identifier first byte should be the algorithm type, second byte the algorithm variant.
> You can create own identifiers, but take a look at [Proposed identifiers](docs/api/1.AlgorithmIdentifier.md)

---
### Encryption Manager - encryption
We already have the EncryptorRegistry, now we can inject it into the 
[EncryptionManager](docs/core/2.EncryptionManager.md). When encrypting, we need to specify the algorithm we want to 
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
Here we wrap the encoded bytes with the [AlgorithmOutput](docs/api/2.AlgorithmOutput.md). Encoded bytes must follow rules of the [Bytes encoding](#bytes-encoding)

```java
AlgorithmOutput output = new AlgorithmOutput( encodedBytes );
byte[] decrypted = manager.decrypt(output, secretKey);
```
> [!NOTE]  
> In this example we don't need to specify the AlgorithmIdentifier because it is already computed in our encoded bytes, 
> along with metadata like the initial vector. 

---

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
- [x] Argon2id
- [x] Argon2i
- [x] Argon2d
- [ ] Bcrypt
- [ ] RSA OAEP
  
New target list will be released after this one is completed
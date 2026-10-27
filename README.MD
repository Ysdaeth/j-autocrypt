# j-autocrypt
Encryption and hashing library to automate decryption and hash verification for various cryptographic algorithms.  
It eliminates the need of storing the algorithm metadata like salt, initial vector, etc.  

> [!NOTE]
> GitHub packages are available to download, but Maven Repository not yet. See [how to install](docs/Installation.md)

Main
- [How to use](#how-to-use)
- [Bytes encoding](#bytes-encoding)
- [Supported algorithms](#supported-algorithms)
- [TODO list](#target-list)
- [Requirements](#requirements)


- [API MODULE](docs/api/0.Api.md)
    - [AlgorithmIdentifier](docs/api/1.AlgorithmIdentifier.md)
    - [AlgorithmOutput](docs/api/2.AlgorithmOutput.md)
    - [Cryptographic](docs/api/3.Cryptographic.md)
    - [Encryptor](docs/api/4.Encryptor.md)
    - [Hasher](docs/api/5.Hasher.md)
    - [KeyedHasher](docs/api/6.KeyedHasher.md)


- [CORE MODULE](docs/core/0.Core.md)
    - [CryptographicRegistry](docs/core/1.CryptographicRegistry.md)
    - [EncryptionManager](docs/core/2.EncryptionManager.md)
    - [HashingManager](docs/core/3.HashingManager.md)

## Bytes encoding
Encoded bytes are bytes produced by the algorithm and are wrapped with the [AlgorithmOutput](docs/api/2.AlgorithmOutput.md).
Encoded bytes are in the following order:
- Algorithm type (1 byte) i.e: AES.
- Algorithm variant (1byte) i.e: GCM
- Metadata bytes (Optional) i.e: metadata length, initial vector, salt, etc.
- Main algorithm bytes (hash or encrypted bytes produced by the implementation)  

Metadata bytes are optional and their presence depends on the algorithm implementation.

## Supported algorithms
[AES](/docs/implementations/1.EncryptorAesGcm.md)  
[HMac](/docs/implementations/2.HasherHMac.md)  
[Sha](/docs/implementations/3.HasherSHA.md)  
[Argon2](/docs/implementations/3.HasherArgon2.md)

## How to use
Take a look at docs  
[Installation](docs/HowToUse.md)  
[How to use](docs/HowToUse.md)

## Requirements
- Java 25
- Designed for OpenJDK
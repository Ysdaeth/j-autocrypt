# j-autocrypt

Encryption and hashing library that automatically handles algorithm resolution, 
eliminating the need to store algorithm metadata for decryption and hash comparison.


---

Core
- [Algorithm Identifier](#algorithmidentifierclass)
- [Bytes encoding](#bytes-encoding)

How to use
- [Introduction](#how-to-use)
- [Encryption manager](#hashing-manager)
- [Hashing manager](#hashing-manager)

Algorithms details
- [AES GCM](#aes-gcm)
- [HMac Sha 224-512](#hmac-sha-224-512)

Other
- [Requirements](#requirements)
- [Target List](#target-list)



## Core
### AlgorithmIdentifier.class
Algorithm identifier represents the bytes pair to identify the algorithm instance.
First byte is for algorithm type identification, for example 'AES', and second byte is algorithm variant like 'GCM'.

### AlgorithmOutput.class
Algorithm output is a wrapper for the encoded bytes created by the algorithm. Structure of the algorithm
output is as follows:
```
encoded = [algorithm type byte],[algorithm variant byte],[remaining bytes]
```
Algorithm type byte identifies algorithm type like 'AES'. Algorithm variant byte identifies variant like 'GCM'.
remaining bytes are bytes that algorithm implementation operates on, and can contain optional algorithm metadata bytes,
which presence depends on the algorithm implementation, and main encrypted bytes.

### Bytes encoding
Encoded bytes are bytes produced by the algorithm, and contain:
- Metadata for algorithm identifier, which contains algorithm type and variant (2 bytes total).
- Algorithm metadata byte array (Optional)
- Main algorithm bytes (hash or encrypted bytes)

Algorithm identifier bytes are required, but algorithm metadata bytes are optional and their presence depends on the
algorithm implementation, i.e: AES GCM metadata bytes are initial vector bytes and metadata length byte
(since IV length can fit within one byte).

## How to use
Encryption manager and Hashing manager provides easier way for encryption and hashing data, without need for a saving
algorithm assigned to the algorithm output, and automatically resolves algorithms used for cryptographic backwards
operations like decryption or hash comparison.

### Encryption manager
Encryption manager creates encoded bytes that contain algorithm identifier bytes, optional algorithm metadata bytes
based on the algorithm instance, and main bytes which are actual encrypted bytes.

#### Encryption
Creating encoded bytes with encrypted bytes, based on the algorithm identifier.
```
EncryptionManager manager = new EncryptionManager();
byte[] secret = new byte[]{1,2,3};
SecretKey key = ...;
Algorithmidentifier identifier = AlgorithmIdentifier.AES_GCM;
AlgorithmOutput encoded = manager.encrypt(secret, key, identifier );
```

#### Decryption
Decryption detects which algorithm should be used for decryption.
```
EncryptionManager manager = new EncryptionManager();
byte[] encoded = // get encoded bytes
AlgorithmOutput output = new AlgorithmOutput(encoded); //wrapper for bytes
SecretKey key = ...; // key used for encryption
byte[] rawData = manager.decrypt(output, key );
```

### Hashing manager
Hashing manager creates encoded bytes that contain algorithm identifier bytes, optional algorithm metadata bytes,
and main bytes which are actual data hash.

#### Hashing
Creating encoded bytes with hash, based on the algorithm identifier.
```
HashingManager manager = new HashingManager();
byte[] data = new byte[]{1,2,3};
SecretKey key = ...;
Algorithmidentifier identifier = AlgorithmIdentifier.H_MAC_SHA256;
AlgorithmOutput encoded = manager.hash(secret, key, identifier ); // with a key because HMac needs a key
```

## Algorithm details

### AES GCM
AES GCM cipher instance is provided from the `java.security.provider`. When encrypting data, a
96bits initial vector is generated with Secure random. Authentication tag is 128bits.
Encoded bytes structure contains algorithm identifier bytes (type and variant), initial vector length in one byte,
since length can be fir with single byte, initial vector byte array and encrypted bytes with authentication tag.
```
encoded = [type],[variant],[ivLen],[iv bytes],[main bytes]
```

### HMac Sha 224-512
Hmac Sha instance is provided from the `java.security.provider`. Creates hash of the given message.
```
encoded = [type],[variant],[main bytes]
```

## Other
### Requirements
- Java 25
- Designed for OpenJDK

### Target list
- [ ] AES CTR
- [ ] AES GCM-SIV
- [ ] Sha 256
- [ ] Sha 384
- [ ] Sha 512
- [ ] Bcrypt
- [ ] Argon2id
- [ ] RSA OAEP
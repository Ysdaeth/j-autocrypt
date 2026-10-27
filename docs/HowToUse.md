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
Encryptor aesEncryptor = new EncryptorAesGcm(identifierAesGcm);

CryptographicRegistry<Encryptor> registry = new CryptographicRegistry<>();
registry.register(aesEncryptor);
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
EncryptionManager encryptionManager = new EncryptionManager(registry);

byte[] secret = "secret".getBytes();
Key secretKey = KeyGenerator.getInstance("AES").generateKey();

AlgorithmOutput output = encryptionManager.encrypt(secret, secretKey, identifierAesGcm);

byte[] encodedBytes = output.getEncoded();
```

---
### Encryption Manager - decryption
Finally, when we want to decrypt our data we can use `encodedBytes` to provide decryptor.
Here we wrap the encoded bytes with the [AlgorithmOutput](docs/api/2.AlgorithmOutput.md). Encoded bytes must follow rules of the [Bytes encoding](#bytes-encoding)

```java
AlgorithmOutput output = new AlgorithmOutput( encodedBytes );
byte[] decrypted = encryptionManager.decrypt(output, secretKey);
```
> [!NOTE]
> In this example we don't need to specify the AlgorithmIdentifier because it is already computed in our encoded bytes,
> along with metadata like the initial vector.

---
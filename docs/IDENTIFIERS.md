# Identifiers bytes convention
Algorithm identifiers require two bytes, where first byte is the algorithm 
type, like AES, RSA, HMAC, etc. second byte is algorithm variant like: GCM, OAEP, SHA256(for HMac).
> [!NOTE] 
> It is possible to use own AlgorithmIdentifier bytes, tables below are only suggestions, not a requirement,
> that's the reason why it was removed from the API module as static variables.

> [!WARNING]
> Byte 0x00 is considered to be undefined and must not be used as an algorithm identifier  
> type or variant

## Encryptors (0x01 to 0x7F)
Encryptor algorithm type byte should be in range 0x01 to 0x07F (inclusive).
Variant byte range 0x01 to 0xFF

### AES
| Name    | Type (byte) | Variant (byte) |  
|---------|-------------|----------------|
| AES ECB | 0x01        | 0x01           |
| AES CBC | 0x01        | 0x02           |
| AES CFB | 0x01        | 0x03           |
| AES OFB | 0x01        | 0x04           |
| AES CTR | 0x01        | 0x05           |
| AES GCM | 0x01        | 0x06           |

### RSA
| Name          | Type (byte) | Variant (byte) |  
|---------------|-------------|----------------|
| RSA NoPadding | 0x02        | 0x01           |
| RSAES PKCS1   | 0x02        | 0x02           |
| RSAES OAEP    | 0x02        | 0x03           |
| RSASSA PSS    | 0x02        | 0x04           |
| RSASA PKCS1   | 0x02        | 0x05           |

## Hashers (0x80 to 0xFF)
Hasher algorithm type byte should be in range 0x80 to 0xFF (inclusive)
Variant byte range 0x01 to 0xFF

### HMac
| Name          | Type (byte) | Variant (byte) |  
|---------------|-------------|----------------|
| HMac MD5      | 0x80        | 0x01           |
| Hmac SHA1     | 0x80        | 0x02           |
| Hmac SHA224   | 0x80        | 0x03           |
| Hmac SHA256   | 0x80        | 0x04           |
| Hmac SHA384   | 0x80        | 0x05           |
| Hmac SHA512   | 0x80        | 0x06           |
| Hmac SHA3-224 | 0x80        | 0x07           |
| Hmac SHA3-256 | 0x80        | 0x08           |
| Hmac SHA3-384 | 0x80        | 0x09           |
| Hmac SHA3-512 | 0x80        | 0x0A           |

### SHA
| Name     | Type (byte) | Variant (byte) |  
|----------|-------------|----------------|
| SHA1     | 0x81        | 0x01           |
| SHA224   | 0x81        | 0x02           |
| SHA256   | 0x81        | 0x03           |
| SHA384   | 0x81        | 0x04           |
| SHA512   | 0x81        | 0x05           |
| SHA3-224 | 0x81        | 0x06           |
| SHA3-256 | 0x81        | 0x07           |
| SHA3-384 | 0x81        | 0x08           |
| SHA3-512 | 0x81        | 0x09           |

### Argon2
| Name     | Type (byte) | Variant (byte) |  
|----------|-------------|----------------|
| Argon2d  | 0x82        | 0x01           |
| Argon2i  | 0x82        | 0x02           |
| Argon2id | 0x82        | 0x03           |
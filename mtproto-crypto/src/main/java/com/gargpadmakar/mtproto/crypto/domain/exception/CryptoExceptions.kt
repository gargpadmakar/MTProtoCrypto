package com.gargpadmakar.mtproto.crypto.domain.exception

/**
 * Base sealed exception for all MTProto cryptographic operations.
 *
 * Security requirement:
 * Sensitive key material or plaintext must NEVER be included in exception messages or logs.
 */
sealed class CryptoException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

class InvalidKeyException(
    message: String = "Cryptographic key is invalid (incorrect length or format)",
    cause: Throwable? = null
) : CryptoException(message, cause)

class InvalidIvException(
    message: String = "Initialization vector is invalid (must be 32 bytes for AES-IGE)",
    cause: Throwable? = null
) : CryptoException(message, cause)

class InvalidCiphertextException(
    message: String = "Ciphertext is invalid, corrupted, or not 16-byte block aligned",
    cause: Throwable? = null
) : CryptoException(message, cause)

class InvalidMessageKeyException(
    message: String = "MTProto msg_key verification failed: message integrity compromise or incorrect auth key",
    cause: Throwable? = null
) : CryptoException(message, cause)

class DHValidationException(
    message: String = "Diffie-Hellman parameter or public key validation failed",
    cause: Throwable? = null
) : CryptoException(message, cause)

class EncryptionException(
    message: String = "Encryption operation failed",
    cause: Throwable? = null
) : CryptoException(message, cause)

class DecryptionException(
    message: String = "Decryption operation failed",
    cause: Throwable? = null
) : CryptoException(message, cause)

class MediaEncryptionException(
    message: String = "Media encryption or streaming operation failed",
    cause: Throwable? = null
) : CryptoException(message, cause)


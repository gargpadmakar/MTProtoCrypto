package com.gargpadmakar.mtproto.crypto.data.crypto

import com.gargpadmakar.mtproto.crypto.domain.exception.DecryptionException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidCiphertextException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidMessageKeyException
import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * High-level MTProto 2.0 Message Encryptor and Decryptor.
 *
 * Implements:
 * - 12..1024 bytes random padding
 * - Message-key calculation and verification
 * - AES-256-IGE encryption & decryption
 * - Constant-time message-key comparison
 * - Automatic buffer zeroization
 */
class MessageCipher(
    private val aesIgeCipher: AesIgeCipher = AesIgeCipher(),
    private val kdf: MTProtoKdf = MTProtoKdf(),
    private val secureRandom: SecureRandom = SecureRandom()
) {

    companion object {
        const val MIN_PADDING_BYTES = 12
        const val MAX_PADDING_BYTES = 1024
        const val HEADER_LENGTH_BYTES = 4
    }

    /**
     * Encrypts plaintext payload using MTProto 2.0 specifications.
     *
     * @param payload Plaintext bytes to encrypt.
     * @param authKey 256-byte authorization key.
     * @param direction Transmission direction (default: CLIENT_TO_SERVER).
     * @return [EncryptedMessage] containing authKeyId, msgKey, and encrypted data.
     */
    fun encrypt(
        payload: ByteArray,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): EncryptedMessage {
        if (authKey.size != MTProtoKdf.AUTH_KEY_SIZE) {
            throw InvalidKeyException("authKey must be 256 bytes")
        }

        // Calculate random padding conforming to MTProto 2.0 (12..1024 bytes, divisible by 16)
        val dataLenWithHeader = HEADER_LENGTH_BYTES + payload.size
        var paddingLen = (16 - (dataLenWithHeader % 16)) % 16
        if (paddingLen < MIN_PADDING_BYTES) {
            paddingLen += 16
        }

        // Add 0..3 extra 16-byte blocks randomly to enhance obfuscation within bounds
        val extraBlocks = secureRandom.nextInt(4)
        paddingLen += extraBlocks * 16

        val totalLength = dataLenWithHeader + paddingLen
        val unencryptedBuffer = ByteArray(totalLength)

        try {
            // Write 4-byte payload length header (big-endian)
            ByteBuffer.wrap(unencryptedBuffer).putInt(payload.size)

            // Copy payload
            System.arraycopy(payload, 0, unencryptedBuffer, HEADER_LENGTH_BYTES, payload.size)

            // Fill padding with cryptographically secure random bytes
            val paddingBytes = ByteArray(paddingLen)
            secureRandom.nextBytes(paddingBytes)
            System.arraycopy(
                paddingBytes,
                0,
                unencryptedBuffer,
                dataLenWithHeader,
                paddingLen
            )
            SecureBytes.wipe(paddingBytes)

            // Calculate msg_key
            val msgKey = kdf.calculateMsgKey(authKey, unencryptedBuffer, direction)

            // Derive AES key and IV
            val derivedKeys = kdf.deriveAesKeyAndIv(authKey, msgKey, direction)

            // Encrypt using AES-256-IGE
            val encryptedData = derivedKeys.use { keys ->
                aesIgeCipher.encrypt(unencryptedBuffer, keys.aesKey, keys.aesIv)
            }

            val authKeyId = kdf.calculateAuthKeyId(authKey)

            return EncryptedMessage(
                authKeyId = authKeyId,
                msgKey = msgKey,
                encryptedData = encryptedData
            )
        } finally {
            SecureBytes.wipe(unencryptedBuffer)
        }
    }

    /**
     * Decrypts an MTProto 2.0 [message] using [authKey].
     *
     * Performs strict constant-time msg_key verification.
     * Never returns plaintext if verification fails.
     */
    fun decrypt(
        message: EncryptedMessage,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): DecryptedMessage {
        if (authKey.size != MTProtoKdf.AUTH_KEY_SIZE) {
            throw InvalidKeyException("authKey must be 256 bytes")
        }

        // Verify auth_key_id matches
        val expectedAuthKeyId = kdf.calculateAuthKeyId(authKey)
        if (!MessageDigest.isEqual(expectedAuthKeyId, message.authKeyId)) {
            throw InvalidKeyException("auth_key_id in message does not match calculated auth_key")
        }

        // Derive AES key and IV
        val derivedKeys = kdf.deriveAesKeyAndIv(authKey, message.msgKey, direction)

        // Decrypt ciphertext with AES-256-IGE
        val decryptedBuffer = derivedKeys.use { keys ->
            aesIgeCipher.decrypt(message.encryptedData, keys.aesKey, keys.aesIv)
        }

        try {
            // Verify msg_key in constant time
            val expectedMsgKey = kdf.calculateMsgKey(authKey, decryptedBuffer, direction)
            val isValid = MessageDigest.isEqual(expectedMsgKey, message.msgKey)
            SecureBytes.wipe(expectedMsgKey)

            if (!isValid) {
                throw InvalidMessageKeyException(
                    "Decrypted message msg_key verification failed. Possible message tampering or wrong key."
                )
            }

            // Extract payload length header
            val payloadLength = ByteBuffer.wrap(decryptedBuffer).int
            val maxPayloadLength = decryptedBuffer.size - HEADER_LENGTH_BYTES - MIN_PADDING_BYTES

            if (payloadLength < 0 || payloadLength > maxPayloadLength) {
                throw InvalidCiphertextException(
                    "Invalid decoded payload length header: $payloadLength"
                )
            }

            val plaintext = ByteArray(payloadLength)
            System.arraycopy(decryptedBuffer, HEADER_LENGTH_BYTES, plaintext, 0, payloadLength)

            val paddingLength = decryptedBuffer.size - HEADER_LENGTH_BYTES - payloadLength

            return DecryptedMessage(
                plaintext = plaintext,
                paddingLength = paddingLength,
                authKeyId = message.authKeyId
            )
        } catch (e: Exception) {
            SecureBytes.wipe(decryptedBuffer)
            if (e is InvalidMessageKeyException || e is InvalidCiphertextException || e is InvalidKeyException) {
                throw e
            }
            throw DecryptionException("Failed to decode message", e)
        } finally {
            SecureBytes.wipe(decryptedBuffer)
        }
    }
}


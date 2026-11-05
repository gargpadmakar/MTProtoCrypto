package com.gargpadmakar.mtproto.crypto.data.crypto

import com.gargpadmakar.mtproto.crypto.domain.exception.DecryptionException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidCiphertextException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidMessageKeyException
import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * End-to-End API Request Encryption & Response Decryption Engine.
 *
 * Implements Telegram MTProto 2.0 dual-layer cryptographic transport:
 * 1. Replay Attack Defense: Embeds 64-bit epoch timestamp & 128-bit cryptographic nonce in inner envelope.
 * 2. Anti-Traffic Analysis: MTProto 2.0 random padding (12..1024 bytes) obfuscates HTTP content length.
 * 3. Directional AES-256-IGE Chaining:
 *    - Client-to-Server Request: offset x = 0
 *    - Server-to-Client Response: offset x = 8
 * 4. Constant-Time Authentication: Validates SHA-256 msg_key prior to releasing plaintext payload.
 * 5. In-Memory Zeroization: Immediately scrubs plaintext buffers and symmetric keys.
 */
class ApiCryptoEngine(
    private val aesIgeCipher: AesIgeCipher = AesIgeCipher(),
    private val kdf: MTProtoKdf = MTProtoKdf(),
    private val secureRandom: SecureRandom = SecureRandom()
) {

    companion object {
        const val NONCE_SIZE_BYTES = 16
        const val TIMESTAMP_SIZE_BYTES = 8
        const val LENGTH_HEADER_BYTES = 4
        const val ENVELOPE_HEADER_SIZE = TIMESTAMP_SIZE_BYTES + NONCE_SIZE_BYTES + LENGTH_HEADER_BYTES
        const val MIN_PADDING_BYTES = 12
        const val DEFAULT_MAX_CLOCK_SKEW_MS = 60000L // 60 seconds
    }

    /**
     * Encrypts an outgoing API request (JSON string or binary) for the server.
     * Uses Client-to-Server directional derivation (x = 0).
     *
     * @param payload Request payload bytes (e.g. JSON.toByteArray()).
     * @param authKey 256-byte session authorization key established via DH exchange.
     * @param timestamp Optional client timestamp (defaults to System.currentTimeMillis()).
     * @return [EncryptedApiPayload] ready to transmit over HTTP/HTTPS.
     */
    fun encryptRequest(
        payload: ByteArray,
        authKey: ByteArray,
        timestamp: Long = System.currentTimeMillis()
    ): EncryptedApiPayload {
        return encryptInternal(
            payload = payload,
            authKey = authKey,
            direction = EncryptionDirection.CLIENT_TO_SERVER,
            timestamp = timestamp
        )
    }

    /**
     * Decrypts an incoming API response from the server.
     * Uses Server-to-Client directional derivation (x = 8).
     *
     * @param encrypted The encrypted API payload received from the server.
     * @param authKey 256-byte session authorization key established via DH exchange.
     * @param maxClockSkewMs Allowed clock drift between client and server (default: 60s).
     * @return [DecryptedApiPayload] containing authenticated plaintext data.
     */
    fun decryptResponse(
        encrypted: EncryptedApiPayload,
        authKey: ByteArray,
        maxClockSkewMs: Long = DEFAULT_MAX_CLOCK_SKEW_MS
    ): DecryptedApiPayload {
        return decryptInternal(
            encrypted = encrypted,
            authKey = authKey,
            direction = EncryptionDirection.SERVER_TO_CLIENT,
            maxClockSkewMs = maxClockSkewMs
        )
    }

    /**
     * Server-side utility or simulator: Decrypts an incoming client request.
     * Uses Client-to-Server directional derivation (x = 0).
     */
    fun decryptRequest(
        encrypted: EncryptedApiPayload,
        authKey: ByteArray,
        maxClockSkewMs: Long = DEFAULT_MAX_CLOCK_SKEW_MS
    ): DecryptedApiPayload {
        return decryptInternal(
            encrypted = encrypted,
            authKey = authKey,
            direction = EncryptionDirection.CLIENT_TO_SERVER,
            maxClockSkewMs = maxClockSkewMs
        )
    }

    /**
     * Server-side utility or simulator: Encrypts an outgoing server response.
     * Uses Server-to-Client directional derivation (x = 8).
     */
    fun encryptResponse(
        payload: ByteArray,
        authKey: ByteArray,
        timestamp: Long = System.currentTimeMillis()
    ): EncryptedApiPayload {
        return encryptInternal(
            payload = payload,
            authKey = authKey,
            direction = EncryptionDirection.SERVER_TO_CLIENT,
            timestamp = timestamp
        )
    }

    private fun encryptInternal(
        payload: ByteArray,
        authKey: ByteArray,
        direction: EncryptionDirection,
        timestamp: Long
    ): EncryptedApiPayload {
        if (authKey.size != MTProtoKdf.AUTH_KEY_SIZE) {
            throw InvalidKeyException("authKey must be 256 bytes")
        }

        // Generate 16-byte random cryptographic nonce
        val nonce = ByteArray(NONCE_SIZE_BYTES)
        secureRandom.nextBytes(nonce)

        val unpaddedLength = ENVELOPE_HEADER_SIZE + payload.size
        var paddingLen = (16 - (unpaddedLength % 16)) % 16
        if (paddingLen < MIN_PADDING_BYTES) {
            paddingLen += 16
        }

        // Add 0..3 extra 16-byte blocks randomly to mask exact length
        val extraBlocks = secureRandom.nextInt(4)
        paddingLen += extraBlocks * 16

        val totalLength = unpaddedLength + paddingLen
        val unencryptedBuffer = ByteArray(totalLength)

        try {
            val byteBuffer = ByteBuffer.wrap(unencryptedBuffer)
            // 8-byte timestamp
            byteBuffer.putLong(timestamp)
            // 16-byte nonce
            byteBuffer.put(nonce)
            // 4-byte payload length
            byteBuffer.putInt(payload.size)
            // payload bytes
            byteBuffer.put(payload)

            // Random padding
            val paddingBytes = ByteArray(paddingLen)
            secureRandom.nextBytes(paddingBytes)
            byteBuffer.put(paddingBytes)
            SecureBytes.wipe(paddingBytes)

            // Calculate msg_key
            val msgKey = kdf.calculateMsgKey(authKey, unencryptedBuffer, direction)

            // Derive AES key and IV
            val derivedKeys = kdf.deriveAesKeyAndIv(authKey, msgKey, direction)

            // Encrypt with AES-256-IGE
            val encryptedData = derivedKeys.use { keys ->
                aesIgeCipher.encrypt(unencryptedBuffer, keys.aesKey, keys.aesIv)
            }

            val authKeyId = ByteBuffer.wrap(kdf.calculateAuthKeyId(authKey)).long

            return EncryptedApiPayload(
                authKeyId = authKeyId,
                msgKey = msgKey,
                ciphertext = encryptedData,
                timestamp = timestamp,
                nonce = nonce
            )
        } finally {
            SecureBytes.wipe(unencryptedBuffer)
        }
    }

    private fun decryptInternal(
        encrypted: EncryptedApiPayload,
        authKey: ByteArray,
        direction: EncryptionDirection,
        maxClockSkewMs: Long
    ): DecryptedApiPayload {
        if (authKey.size != MTProtoKdf.AUTH_KEY_SIZE) {
            throw InvalidKeyException("authKey must be 256 bytes")
        }

        if (encrypted.ciphertext.isEmpty() || encrypted.ciphertext.size % 16 != 0) {
            throw InvalidCiphertextException("Ciphertext length must be non-empty and a multiple of 16")
        }

        if (encrypted.msgKey.size != MTProtoKdf.MSG_KEY_SIZE) {
            throw InvalidMessageKeyException("msgKey must be exactly 16 bytes")
        }

        val expectedAuthKeyId = ByteBuffer.wrap(kdf.calculateAuthKeyId(authKey)).long
        if (encrypted.authKeyId != expectedAuthKeyId) {
            throw InvalidKeyException("authKeyId mismatch: expected $expectedAuthKeyId, got ${encrypted.authKeyId}")
        }

        // Derive AES key and IV
        val derivedKeys = kdf.deriveAesKeyAndIv(authKey, encrypted.msgKey, direction)

        val decryptedBuffer = derivedKeys.use { keys ->
            aesIgeCipher.decrypt(encrypted.ciphertext, keys.aesKey, keys.aesIv)
        }

        try {
            // Verify msg_key in constant time
            val calculatedMsgKey = kdf.calculateMsgKey(authKey, decryptedBuffer, direction)
            if (!MessageDigest.isEqual(calculatedMsgKey, encrypted.msgKey)) {
                throw InvalidMessageKeyException("Message key verification failed. Data corrupted or tampered.")
            }

            if (decryptedBuffer.size < ENVELOPE_HEADER_SIZE + MIN_PADDING_BYTES) {
                throw DecryptionException("Decrypted buffer size is too small for valid envelope")
            }

            val byteBuffer = ByteBuffer.wrap(decryptedBuffer)
            val timestamp = byteBuffer.long
            val nonce = ByteArray(NONCE_SIZE_BYTES)
            byteBuffer.get(nonce)
            val payloadLength = byteBuffer.int

            if (payloadLength < 0 || payloadLength > decryptedBuffer.size - ENVELOPE_HEADER_SIZE - MIN_PADDING_BYTES) {
                throw DecryptionException("Invalid payload length field: $payloadLength")
            }

            // Verify replay window if maxClockSkewMs is configured
            if (maxClockSkewMs > 0) {
                val now = System.currentTimeMillis()
                val delta = Math.abs(now - timestamp)
                if (delta > maxClockSkewMs) {
                    throw DecryptionException("Replay attack detected or clock out of sync: skew was ${delta}ms (allowed: ${maxClockSkewMs}ms)")
                }
            }

            val payload = ByteArray(payloadLength)
            byteBuffer.get(payload)

            return DecryptedApiPayload(
                data = payload,
                timestamp = timestamp,
                nonce = nonce
            )
        } finally {
            SecureBytes.wipe(decryptedBuffer)
        }
    }
}

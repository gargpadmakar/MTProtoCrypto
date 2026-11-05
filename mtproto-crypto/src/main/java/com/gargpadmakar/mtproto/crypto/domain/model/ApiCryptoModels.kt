package com.gargpadmakar.mtproto.crypto.domain.model

import java.util.Base64

/**
 * Model representing an encrypted API request or response payload.
 *
 * @property authKeyId 64-bit identifier of the negotiated session authorization key.
 * @property msgKey 128-bit (16-byte) MTProto 2.0 message key computed from payload.
 * @property ciphertext AES-256-IGE encrypted payload bytes.
 * @property timestamp Unix epoch timestamp in milliseconds when payload was created (anti-replay).
 * @property nonce Optional 16-byte cryptographically secure random token (anti-replay).
 */
data class EncryptedApiPayload(
    val authKeyId: Long,
    val msgKey: ByteArray,
    val ciphertext: ByteArray,
    val timestamp: Long = System.currentTimeMillis(),
    val nonce: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedApiPayload
        if (authKeyId != other.authKeyId) return false
        if (!msgKey.contentEquals(other.msgKey)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (timestamp != other.timestamp) return false
        if (nonce != null) {
            if (other.nonce == null || !nonce.contentEquals(other.nonce)) return false
        } else if (other.nonce != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = authKeyId.hashCode()
        result = 31 * result + msgKey.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + (nonce?.contentHashCode() ?: 0)
        return result
    }

    /**
     * Converts the encrypted payload into a clean JSON string ready to be transmitted
     * as HTTP POST body (application/json).
     */
    fun toJson(): String {
        val encoder = Base64.getEncoder()
        val msgKeyB64 = encoder.encodeToString(msgKey)
        val cipherB64 = encoder.encodeToString(ciphertext)
        val nonceB64 = nonce?.let { encoder.encodeToString(it) } ?: ""

        return "{" +
                "\"auth_key_id\":\"$authKeyId\"," +
                "\"msg_key\":\"$msgKeyB64\"," +
                "\"payload\":\"$cipherB64\"," +
                "\"timestamp\":$timestamp" +
                (if (nonceB64.isNotEmpty()) ",\"nonce\":\"$nonceB64\"" else "") +
                "}"
    }

    companion object {
        /**
         * Parses JSON string into an [EncryptedApiPayload].
         */
        fun fromJson(json: String): EncryptedApiPayload {
            val decoder = Base64.getDecoder()

            fun extractString(key: String): String {
                val pattern = "\"$key\"\\s*:\\s*\"([^\"]+)\"".toRegex()
                return pattern.find(json)?.groupValues?.get(1)
                    ?: throw IllegalArgumentException("Missing key in JSON: $key")
            }

            fun extractLong(key: String): Long {
                val pattern = "\"$key\"\\s*:\\s*(\\d+)".toRegex()
                val match = pattern.find(json)?.groupValues?.get(1)
                return match?.toLongOrNull() ?: System.currentTimeMillis()
            }

            val authKeyId = extractString("auth_key_id").toLong()
            val msgKey = decoder.decode(extractString("msg_key"))
            val payload = decoder.decode(extractString("payload"))
            val timestamp = extractLong("timestamp")

            val nonce = try {
                decoder.decode(extractString("nonce"))
            } catch (e: Exception) {
                null
            }

            return EncryptedApiPayload(
                authKeyId = authKeyId,
                msgKey = msgKey,
                ciphertext = payload,
                timestamp = timestamp,
                nonce = nonce
            )
        }
    }
}

/**
 * Model representing a successfully decrypted and authenticated API payload.
 *
 * @property data The decrypted plaintext bytes (JSON, Protobuf, or arbitrary binary).
 * @property timestamp The timestamp when the remote party produced the payload.
 * @property nonce The cryptographic nonce included in the payload.
 */
data class DecryptedApiPayload(
    val data: ByteArray,
    val timestamp: Long,
    val nonce: ByteArray? = null
) {
    /**
     * Helper to read the payload as UTF-8 string (e.g. JSON).
     */
    val utf8String: String
        get() = String(data, Charsets.UTF_8)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DecryptedApiPayload
        if (!data.contentEquals(other.data)) return false
        if (timestamp != other.timestamp) return false
        if (nonce != null) {
            if (other.nonce == null || !nonce.contentEquals(other.nonce)) return false
        } else if (other.nonce != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + (nonce?.contentHashCode() ?: 0)
        return result
    }
}


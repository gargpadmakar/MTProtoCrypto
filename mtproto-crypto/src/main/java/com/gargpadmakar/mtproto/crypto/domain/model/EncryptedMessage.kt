package com.gargpadmakar.mtproto.crypto.domain.model

import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidCiphertextException
import java.util.Base64

/**
 * MTProto 2.0 Encrypted Message container.
 *
 * Wire Structure:
 * - authKeyId: 8 bytes (lower 64 bits of SHA-1 of auth_key)
 * - msgKey: 16 bytes (middle 128 bits of SHA-256(auth_key_part + payload + padding))
 * - encryptedData: AES-IGE encrypted (payload + padding), size is multiple of 16
 */
data class EncryptedMessage(
    val authKeyId: ByteArray,
    val msgKey: ByteArray,
    val encryptedData: ByteArray
) {
    init {
        require(authKeyId.size == 8) { "authKeyId must be 8 bytes" }
        require(msgKey.size == 16) { "msgKey must be 16 bytes" }
        require(encryptedData.isNotEmpty() && encryptedData.size % 16 == 0) {
            "encryptedData must be non-empty and multiple of 16 bytes"
        }
    }

    /**
     * Serializes to official MTProto wire byte array: authKeyId (8) + msgKey (16) + encryptedData (N).
     */
    fun toWireBytes(): ByteArray {
        val wire = ByteArray(8 + 16 + encryptedData.size)
        System.arraycopy(authKeyId, 0, wire, 0, 8)
        System.arraycopy(msgKey, 0, wire, 8, 16)
        System.arraycopy(encryptedData, 0, wire, 24, encryptedData.size)
        return wire
    }

    fun toBase64(): String {
        return Base64.getEncoder().encodeToString(toWireBytes())
    }

    fun toHex(): String {
        val wire = toWireBytes()
        val sb = StringBuilder(wire.size * 2)
        for (b in wire) {
            val v = b.toInt() and 0xFF
            if (v < 16) sb.append('0')
            sb.append(Integer.toHexString(v))
        }
        return sb.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedMessage) return false
        return authKeyId.contentEquals(other.authKeyId) &&
                msgKey.contentEquals(other.msgKey) &&
                encryptedData.contentEquals(other.encryptedData)
    }

    override fun hashCode(): Int {
        var result = authKeyId.contentHashCode()
        result = 31 * result + msgKey.contentHashCode()
        result = 31 * result + encryptedData.contentHashCode()
        return result
    }

    companion object {
        fun fromWireBytes(wireBytes: ByteArray): EncryptedMessage {
            if (wireBytes.size < 24 + 16) {
                throw InvalidCiphertextException(
                    "Wire bytes too short (${wireBytes.size} bytes). Minimum is 40 bytes (8 + 16 + 16)"
                )
            }
            val encryptedLen = wireBytes.size - 24
            if (encryptedLen % 16 != 0) {
                throw InvalidCiphertextException(
                    "Encrypted data length ($encryptedLen) must be a multiple of 16"
                )
            }

            val authKeyId = ByteArray(8)
            val msgKey = ByteArray(16)
            val encryptedData = ByteArray(encryptedLen)

            System.arraycopy(wireBytes, 0, authKeyId, 0, 8)
            System.arraycopy(wireBytes, 8, msgKey, 0, 16)
            System.arraycopy(wireBytes, 24, encryptedData, 0, encryptedLen)

            return EncryptedMessage(authKeyId, msgKey, encryptedData)
        }

        fun fromBase64(base64Str: String): EncryptedMessage {
            val bytes = Base64.getDecoder().decode(base64Str.trim())
            return fromWireBytes(bytes)
        }
    }
}


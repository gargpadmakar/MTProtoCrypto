package com.gargpadmakar.mtproto.crypto.domain.model

import com.gargpadmakar.mtproto.crypto.security.SecureBytes

/**
 * Result of successful MTProto 2.0 message decryption and integrity verification.
 * Contains verified plaintext payload and padding length.
 */
class DecryptedMessage(
    val plaintext: ByteArray,
    val paddingLength: Int,
    val authKeyId: ByteArray
) : AutoCloseable {

    fun text(): String {
        return String(plaintext, Charsets.UTF_8)
    }

    fun wipe() {
        SecureBytes.wipe(plaintext)
    }

    override fun close() {
        wipe()
    }
}


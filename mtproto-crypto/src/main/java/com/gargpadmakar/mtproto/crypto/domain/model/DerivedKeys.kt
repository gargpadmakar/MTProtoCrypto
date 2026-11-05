package com.gargpadmakar.mtproto.crypto.domain.model

import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import java.util.Arrays

/**
 * Container holding derived 256-bit AES key and 256-bit AES-IGE IV.
 * Caller must call [wipe] or use inside [use] to zeroize sensitive key material.
 */
class DerivedKeys(
    val aesKey: ByteArray,
    val aesIv: ByteArray
) : AutoCloseable {

    init {
        require(aesKey.size == 32) { "AES key must be 32 bytes" }
        require(aesIv.size == 32) { "AES IV must be 32 bytes" }
    }

    fun wipe() {
        SecureBytes.wipe(aesKey)
        SecureBytes.wipe(aesIv)
    }

    override fun close() {
        wipe()
    }
}


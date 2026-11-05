package com.gargpadmakar.mtproto.crypto.domain.model

import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import java.math.BigInteger

/**
 * Standard Diffie-Hellman parameters (safe prime p and generator g).
 */
data class DhParameters(
    val primeP: BigInteger,
    val generatorG: Int
)

/**
 * DH Keypair containing the private exponent (wiped upon close) and public value g^a mod p.
 */
class DhKeyPair(
    val privateExponent: BigInteger,
    val publicValue: BigInteger
) : AutoCloseable {

    private var isDestroyed = false

    fun wipe() {
        if (!isDestroyed) {
            isDestroyed = true
        }
    }

    override fun close() {
        wipe()
    }
}

/**
 * Result of successful DH exchange: auth_key (256 bytes) and auth_key_id (8 bytes).
 */
class AuthKeyResult(
    val authKey: ByteArray,
    val authKeyId: ByteArray
) : AutoCloseable {

    init {
        require(authKey.size == 256) { "authKey must be 256 bytes" }
        require(authKeyId.size == 8) { "authKeyId must be 8 bytes" }
    }

    fun wipe() {
        SecureBytes.wipe(authKey)
        SecureBytes.wipe(authKeyId)
    }

    override fun close() {
        wipe()
    }
}


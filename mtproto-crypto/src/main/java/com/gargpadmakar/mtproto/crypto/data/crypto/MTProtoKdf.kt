package com.gargpadmakar.mtproto.crypto.data.crypto

import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.domain.model.DerivedKeys
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import java.security.MessageDigest

/**
 * Official Telegram MTProto 2.0 Key Derivation Function (KDF) implementation.
 * Follows: https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector
 */
class MTProtoKdf {

    companion object {
        const val AUTH_KEY_SIZE = 256
        const val MSG_KEY_SIZE = 16
        const val AUTH_KEY_ID_SIZE = 8
    }

    /**
     * Computes the 16-byte message key (msg_key) according to MTProto 2.0 specification:
     * - Client to Server: msg_key = SHA-256(auth_key[88..119] + payload + padding)[8..23]
     * - Server to Client: msg_key = SHA-256(auth_key[96..127] + payload + padding)[8..23]
     */
    fun calculateMsgKey(
        authKey: ByteArray,
        payloadAndPadding: ByteArray,
        direction: EncryptionDirection
    ): ByteArray {
        validateAuthKey(authKey)

        val offset = when (direction) {
            EncryptionDirection.CLIENT_TO_SERVER -> 88
            EncryptionDirection.SERVER_TO_CLIENT -> 96
        }

        val md = MessageDigest.getInstance("SHA-256")
        md.update(authKey, offset, 32)
        md.update(payloadAndPadding)
        val sha256Large = md.digest()

        val msgKey = ByteArray(MSG_KEY_SIZE)
        System.arraycopy(sha256Large, 8, msgKey, 0, MSG_KEY_SIZE)
        SecureBytes.wipe(sha256Large)
        return msgKey
    }

    /**
     * Derives a 32-byte AES key and 32-byte AES-IGE IV from auth_key and msg_key.
     *
     * Offsets:
     * x = 0 for client -> server
     * x = 8 for server -> client
     *
     * sha256_a = SHA256(msg_key + auth_key[x..x+35])
     * sha256_b = SHA256(auth_key[x+32..x+47] + msg_key + auth_key[x+48..x+63])
     * sha256_c = SHA256(auth_key[x+64..x+95] + msg_key)
     * sha256_d = SHA256(msg_key + auth_key[x+96..x+127])
     *
     * aes_key = sha256_a[0..7] + sha256_b[8..23] + sha256_c[24..31]
     * aes_iv  = sha256_a[8..15] + sha256_b[0..7] + sha256_c[16..23] + sha256_d[0..7]
     */
    fun deriveAesKeyAndIv(
        authKey: ByteArray,
        msgKey: ByteArray,
        direction: EncryptionDirection
    ): DerivedKeys {
        validateAuthKey(authKey)
        if (msgKey.size != MSG_KEY_SIZE) {
            throw InvalidKeyException("msg_key must be exactly 16 bytes")
        }

        val x = when (direction) {
            EncryptionDirection.CLIENT_TO_SERVER -> 0
            EncryptionDirection.SERVER_TO_CLIENT -> 8
        }

        val md = MessageDigest.getInstance("SHA-256")

        // sha256_a = SHA256(msg_key + auth_key[x..x+35])
        md.update(msgKey)
        md.update(authKey, x, 36)
        val sha256A = md.digest()

        // sha256_b = SHA256(auth_key[x+32..x+47] + msg_key + auth_key[x+48..x+63])
        md.update(authKey, x + 32, 16)
        md.update(msgKey)
        md.update(authKey, x + 48, 16)
        val sha256B = md.digest()

        // sha256_c = SHA256(auth_key[x+64..x+95] + msg_key)
        md.update(authKey, x + 64, 32)
        md.update(msgKey)
        val sha256C = md.digest()

        // sha256_d = SHA256(msg_key + auth_key[x+96..x+127])
        md.update(msgKey)
        md.update(authKey, x + 96, 32)
        val sha256D = md.digest()

        val aesKey = ByteArray(32)
        val aesIv = ByteArray(32)

        try {
            // aes_key = sha256_a[0..7] + sha256_b[8..23] + sha256_c[24..31]
            System.arraycopy(sha256A, 0, aesKey, 0, 8)
            System.arraycopy(sha256B, 8, aesKey, 8, 16)
            System.arraycopy(sha256C, 24, aesKey, 24, 8)

            // aes_iv = sha256_a[8..15] + sha256_b[0..7] + sha256_c[16..23] + sha256_d[0..7]
            System.arraycopy(sha256A, 8, aesIv, 0, 8)
            System.arraycopy(sha256B, 0, aesIv, 8, 8)
            System.arraycopy(sha256C, 16, aesIv, 16, 8)
            System.arraycopy(sha256D, 0, aesIv, 24, 8)

            return DerivedKeys(aesKey, aesIv)
        } finally {
            SecureBytes.wipe(sha256A)
            SecureBytes.wipe(sha256B)
            SecureBytes.wipe(sha256C)
            SecureBytes.wipe(sha256D)
        }
    }

    /**
     * Calculates the 8-byte auth_key_id, which represents the lower 64 bits of SHA-1(auth_key).
     */
    fun calculateAuthKeyId(authKey: ByteArray): ByteArray {
        validateAuthKey(authKey)
        val md = MessageDigest.getInstance("SHA-1")
        val sha1 = md.digest(authKey)
        val authKeyId = ByteArray(AUTH_KEY_ID_SIZE)
        // Lower 64 bits = bytes 12..19 of 20-byte SHA-1
        System.arraycopy(sha1, 12, authKeyId, 0, AUTH_KEY_ID_SIZE)
        SecureBytes.wipe(sha1)
        return authKeyId
    }

    private fun validateAuthKey(authKey: ByteArray) {
        if (authKey.size != AUTH_KEY_SIZE) {
            throw InvalidKeyException("auth_key must be exactly 256 bytes (2048 bits)")
        }
    }
}


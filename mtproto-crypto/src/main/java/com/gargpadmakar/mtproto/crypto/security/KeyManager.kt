package com.gargpadmakar.mtproto.crypto.security

import com.gargpadmakar.mtproto.crypto.domain.model.AuthKeyResult
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe in-memory authorization key store with zeroization lifecycle management.
 */
class KeyManager {

    private val authKeys = ConcurrentHashMap<String, ByteArray>()

    /**
     * Registers an authorization key indexed by its hex auth_key_id.
     */
    fun storeAuthKey(authKeyResult: AuthKeyResult) {
        val idHex = toHex(authKeyResult.authKeyId)
        val copy = authKeyResult.authKey.clone()
        val old = authKeys.put(idHex, copy)
        SecureBytes.wipe(old)
    }

    /**
     * Stores an auth key directly by id.
     */
    fun storeAuthKey(authKeyId: ByteArray, authKey: ByteArray) {
        val idHex = toHex(authKeyId)
        val copy = authKey.clone()
        val old = authKeys.put(idHex, copy)
        SecureBytes.wipe(old)
    }

    /**
     * Retrieves a defensive copy of the auth_key for the given authKeyId.
     * The caller is responsible for wiping the returned array after use.
     */
    fun getAuthKey(authKeyId: ByteArray): ByteArray? {
        val idHex = toHex(authKeyId)
        return authKeys[idHex]?.clone()
    }

    /**
     * Removes and wipes the auth key associated with authKeyId.
     */
    fun removeAuthKey(authKeyId: ByteArray) {
        val idHex = toHex(authKeyId)
        val removed = authKeys.remove(idHex)
        SecureBytes.wipe(removed)
    }

    /**
     * Wipes and clears all stored keys.
     */
    fun clearAll() {
        for ((_, key) in authKeys) {
            SecureBytes.wipe(key)
        }
        authKeys.clear()
    }

    private fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            if (v < 16) sb.append('0')
            sb.append(Integer.toHexString(v))
        }
        return sb.toString()
    }
}


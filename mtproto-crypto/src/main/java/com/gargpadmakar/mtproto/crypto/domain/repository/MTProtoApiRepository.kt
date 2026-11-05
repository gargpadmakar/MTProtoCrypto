package com.gargpadmakar.mtproto.crypto.domain.repository

import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload

/**
 * Repository interface for API Request Payload Encryption and Response Decryption.
 */
interface MTProtoApiRepository {

    /**
     * Encrypts outgoing client API request using MTProto 2.0 Client-to-Server KDF (x = 0).
     */
    suspend fun encryptRequest(
        payload: ByteArray,
        authKey: ByteArray,
        timestamp: Long = System.currentTimeMillis()
    ): EncryptedApiPayload

    /**
     * Decrypts incoming server API response using MTProto 2.0 Server-to-Client KDF (x = 8).
     */
    suspend fun decryptResponse(
        encrypted: EncryptedApiPayload,
        authKey: ByteArray,
        maxClockSkewMs: Long = 60000L
    ): DecryptedApiPayload
}

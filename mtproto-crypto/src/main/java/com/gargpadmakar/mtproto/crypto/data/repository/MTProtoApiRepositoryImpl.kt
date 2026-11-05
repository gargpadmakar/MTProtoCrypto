package com.gargpadmakar.mtproto.crypto.data.repository

import com.gargpadmakar.mtproto.crypto.data.crypto.ApiCryptoEngine
import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoApiRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Implementation of [MTProtoApiRepository] performing cryptographic operations
 * on the default background coroutine dispatcher.
 */
class MTProtoApiRepositoryImpl(
    private val apiCryptoEngine: ApiCryptoEngine = ApiCryptoEngine()
) : MTProtoApiRepository {

    override suspend fun encryptRequest(
        payload: ByteArray,
        authKey: ByteArray,
        timestamp: Long
    ): EncryptedApiPayload = withContext(Dispatchers.Default) {
        apiCryptoEngine.encryptRequest(payload, authKey, timestamp)
    }

    override suspend fun decryptResponse(
        encrypted: EncryptedApiPayload,
        authKey: ByteArray,
        maxClockSkewMs: Long
    ): DecryptedApiPayload = withContext(Dispatchers.Default) {
        apiCryptoEngine.decryptResponse(encrypted, authKey, maxClockSkewMs)
    }
}


package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoApiRepository

/**
 * UseCase to decrypt an incoming server API response and verify its authenticity.
 */
class DecryptApiResponseUseCase(
    private val apiRepository: MTProtoApiRepository
) {
    suspend operator fun invoke(
        encrypted: EncryptedApiPayload,
        authKey: ByteArray,
        maxClockSkewMs: Long = 60000L
    ): Result<DecryptedApiPayload> {
        return runCatching {
            apiRepository.decryptResponse(encrypted, authKey, maxClockSkewMs)
        }
    }
}

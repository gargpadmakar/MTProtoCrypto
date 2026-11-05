package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoApiRepository

/**
 * UseCase to encrypt an outgoing API request (JSON string or binary bytes).
 */
class EncryptApiRequestUseCase(
    private val apiRepository: MTProtoApiRepository
) {
    /**
     * Encrypts a JSON or UTF-8 text request.
     */
    suspend operator fun invoke(
        jsonText: String,
        authKey: ByteArray,
        timestamp: Long = System.currentTimeMillis()
    ): Result<EncryptedApiPayload> {
        return runCatching {
            require(jsonText.isNotEmpty()) { "Request payload cannot be empty" }
            apiRepository.encryptRequest(jsonText.toByteArray(Charsets.UTF_8), authKey, timestamp)
        }
    }

    /**
     * Encrypts raw binary bytes.
     */
    suspend operator fun invoke(
        payload: ByteArray,
        authKey: ByteArray,
        timestamp: Long = System.currentTimeMillis()
    ): Result<EncryptedApiPayload> {
        return runCatching {
            require(payload.isNotEmpty()) { "Request payload cannot be empty" }
            apiRepository.encryptRequest(payload, authKey, timestamp)
        }
    }
}


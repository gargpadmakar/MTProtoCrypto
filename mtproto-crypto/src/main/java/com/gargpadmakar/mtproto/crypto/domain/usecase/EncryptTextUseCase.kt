package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoCipherRepository

/**
 * UseCase to encrypt plaintext text or data using MTProto 2.0 message encryption.
 */
class EncryptTextUseCase(
    private val cipherRepository: MTProtoCipherRepository
) {
    suspend operator fun invoke(
        text: String,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): Result<EncryptedMessage> {
        return runCatching {
            require(text.isNotEmpty()) { "Plaintext cannot be empty" }
            val payload = text.toByteArray(Charsets.UTF_8)
            cipherRepository.encryptMessage(payload, authKey, direction)
        }
    }

    suspend operator fun invoke(
        payload: ByteArray,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): Result<EncryptedMessage> {
        return runCatching {
            require(payload.isNotEmpty()) { "Payload cannot be empty" }
            cipherRepository.encryptMessage(payload, authKey, direction)
        }
    }
}


package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoCipherRepository

/**
 * UseCase to decrypt an MTProto 2.0 message and verify its integrity in constant time.
 */
class DecryptTextUseCase(
    private val cipherRepository: MTProtoCipherRepository
) {
    suspend operator fun invoke(
        message: EncryptedMessage,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): Result<DecryptedMessage> {
        return runCatching {
            cipherRepository.decryptMessage(message, authKey, direction)
        }
    }

    suspend operator fun invoke(
        wireBytes: ByteArray,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): Result<DecryptedMessage> {
        return runCatching {
            val message = EncryptedMessage.fromWireBytes(wireBytes)
            cipherRepository.decryptMessage(message, authKey, direction)
        }
    }

    suspend operator fun invoke(
        base64Wire: String,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): Result<DecryptedMessage> {
        return runCatching {
            val message = EncryptedMessage.fromBase64(base64Wire)
            cipherRepository.decryptMessage(message, authKey, direction)
        }
    }
}


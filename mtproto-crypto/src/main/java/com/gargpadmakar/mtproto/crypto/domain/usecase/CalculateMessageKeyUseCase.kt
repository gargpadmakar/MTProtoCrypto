package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoKdfRepository

/**
 * UseCase to calculate 16-byte MTProto 2.0 message key (msg_key).
 */
class CalculateMessageKeyUseCase(
    private val kdfRepository: MTProtoKdfRepository
) {
    operator fun invoke(
        authKey: ByteArray,
        payloadAndPadding: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): Result<ByteArray> {
        return runCatching {
            kdfRepository.calculateMsgKey(authKey, payloadAndPadding, direction)
        }
    }
}


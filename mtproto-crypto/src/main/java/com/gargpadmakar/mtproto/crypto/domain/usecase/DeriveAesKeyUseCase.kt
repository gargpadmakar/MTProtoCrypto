package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.DerivedKeys
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoKdfRepository

/**
 * UseCase to derive 256-bit AES key and 256-bit AES-IGE IV using official MTProto 2.0 KDF.
 */
class DeriveAesKeyUseCase(
    private val kdfRepository: MTProtoKdfRepository
) {
    operator fun invoke(
        authKey: ByteArray,
        msgKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): Result<DerivedKeys> {
        return runCatching {
            kdfRepository.deriveAesKeyAndIv(authKey, msgKey, direction)
        }
    }
}


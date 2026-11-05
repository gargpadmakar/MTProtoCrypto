package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.DhParameters
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoHandshakeRepository
import java.math.BigInteger

/**
 * UseCase to validate Diffie-Hellman parameters and public values.
 */
class ValidateDhParametersUseCase(
    private val handshakeRepository: MTProtoHandshakeRepository
) {
    operator fun invoke(params: DhParameters): Result<Unit> {
        return runCatching {
            handshakeRepository.validateParameters(params)
        }
    }

    operator fun invoke(publicValue: BigInteger, primeP: BigInteger): Result<Unit> {
        return runCatching {
            handshakeRepository.validatePublicValue(publicValue, primeP)
        }
    }
}


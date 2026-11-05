package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.AuthKeyResult
import com.gargpadmakar.mtproto.crypto.domain.model.DhKeyPair
import com.gargpadmakar.mtproto.crypto.domain.model.DhParameters
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoHandshakeRepository
import java.math.BigInteger

/**
 * UseCase to generate authorization key via Diffie-Hellman key exchange.
 */
class GenerateAuthorizationKeyUseCase(
    private val handshakeRepository: MTProtoHandshakeRepository
) {
    fun getDefaultParameters(): DhParameters {
        return handshakeRepository.getDefaultDhParameters()
    }

    fun generateKeyPair(params: DhParameters = getDefaultParameters()): DhKeyPair {
        return handshakeRepository.generateKeyPair(params)
    }

    operator fun invoke(
        peerPublicValue: BigInteger,
        privateExponent: BigInteger,
        params: DhParameters = getDefaultParameters()
    ): Result<AuthKeyResult> {
        return runCatching {
            handshakeRepository.computeAuthKey(peerPublicValue, privateExponent, params)
        }
    }
}


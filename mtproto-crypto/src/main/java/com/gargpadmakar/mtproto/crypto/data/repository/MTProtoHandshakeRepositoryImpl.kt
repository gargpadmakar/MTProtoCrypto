package com.gargpadmakar.mtproto.crypto.data.repository

import com.gargpadmakar.mtproto.crypto.data.crypto.DhHandshakeEngine
import com.gargpadmakar.mtproto.crypto.domain.model.AuthKeyResult
import com.gargpadmakar.mtproto.crypto.domain.model.DhKeyPair
import com.gargpadmakar.mtproto.crypto.domain.model.DhParameters
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoHandshakeRepository
import java.math.BigInteger

class MTProtoHandshakeRepositoryImpl(
    private val handshakeEngine: DhHandshakeEngine = DhHandshakeEngine()
) : MTProtoHandshakeRepository {

    override fun getDefaultDhParameters(): DhParameters {
        return DhHandshakeEngine.DEFAULT_DH_PARAMETERS
    }

    override fun validateParameters(params: DhParameters) {
        handshakeEngine.validateDhParameters(params)
    }

    override fun validatePublicValue(publicValue: BigInteger, primeP: BigInteger) {
        handshakeEngine.validatePublicValue(publicValue, primeP)
    }

    override fun generateKeyPair(params: DhParameters): DhKeyPair {
        return handshakeEngine.generateKeyPair(params)
    }

    override fun computeAuthKey(
        peerPublicValue: BigInteger,
        privateExponent: BigInteger,
        params: DhParameters
    ): AuthKeyResult {
        return handshakeEngine.computeAuthKey(peerPublicValue, privateExponent, params)
    }
}


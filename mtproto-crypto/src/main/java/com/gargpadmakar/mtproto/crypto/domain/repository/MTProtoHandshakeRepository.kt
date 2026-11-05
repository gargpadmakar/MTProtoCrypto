package com.gargpadmakar.mtproto.crypto.domain.repository

import com.gargpadmakar.mtproto.crypto.domain.model.AuthKeyResult
import com.gargpadmakar.mtproto.crypto.domain.model.DhKeyPair
import com.gargpadmakar.mtproto.crypto.domain.model.DhParameters
import java.math.BigInteger

/**
 * Pure Kotlin repository interface for MTProto Diffie-Hellman Handshake and Authorization Key Exchange.
 */
interface MTProtoHandshakeRepository {
    fun getDefaultDhParameters(): DhParameters

    fun validateParameters(params: DhParameters)

    fun validatePublicValue(publicValue: BigInteger, primeP: BigInteger)

    fun generateKeyPair(params: DhParameters): DhKeyPair

    fun computeAuthKey(
        peerPublicValue: BigInteger,
        privateExponent: BigInteger,
        params: DhParameters
    ): AuthKeyResult
}


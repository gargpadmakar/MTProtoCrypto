package com.gargpadmakar.mtproto.crypto.data.repository

import com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf
import com.gargpadmakar.mtproto.crypto.domain.model.DerivedKeys
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoKdfRepository

class MTProtoKdfRepositoryImpl(
    private val kdf: MTProtoKdf = MTProtoKdf()
) : MTProtoKdfRepository {

    override fun calculateMsgKey(
        authKey: ByteArray,
        payloadAndPadding: ByteArray,
        direction: EncryptionDirection
    ): ByteArray {
        return kdf.calculateMsgKey(authKey, payloadAndPadding, direction)
    }

    override fun deriveAesKeyAndIv(
        authKey: ByteArray,
        msgKey: ByteArray,
        direction: EncryptionDirection
    ): DerivedKeys {
        return kdf.deriveAesKeyAndIv(authKey, msgKey, direction)
    }

    override fun calculateAuthKeyId(authKey: ByteArray): ByteArray {
        return kdf.calculateAuthKeyId(authKey)
    }
}


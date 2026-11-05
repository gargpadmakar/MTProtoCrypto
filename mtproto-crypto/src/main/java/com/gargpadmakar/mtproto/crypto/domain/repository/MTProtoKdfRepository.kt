package com.gargpadmakar.mtproto.crypto.domain.repository

import com.gargpadmakar.mtproto.crypto.domain.model.DerivedKeys
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection

/**
 * Pure Kotlin repository interface for MTProto 2.0 Key Derivation Function (KDF).
 */
interface MTProtoKdfRepository {
    fun calculateMsgKey(
        authKey: ByteArray,
        payloadAndPadding: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): ByteArray

    fun deriveAesKeyAndIv(
        authKey: ByteArray,
        msgKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): DerivedKeys

    fun calculateAuthKeyId(authKey: ByteArray): ByteArray
}


package com.gargpadmakar.mtproto.crypto.domain.repository

import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection

/**
 * Pure Kotlin repository interface for MTProto 2.0 message encryption and raw AES-IGE operations.
 */
interface MTProtoCipherRepository {
    suspend fun encryptMessage(
        payload: ByteArray,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): EncryptedMessage

    suspend fun decryptMessage(
        message: EncryptedMessage,
        authKey: ByteArray,
        direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER
    ): DecryptedMessage

    suspend fun encryptAesIge(
        plaintext: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray

    suspend fun decryptAesIge(
        ciphertext: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray
}


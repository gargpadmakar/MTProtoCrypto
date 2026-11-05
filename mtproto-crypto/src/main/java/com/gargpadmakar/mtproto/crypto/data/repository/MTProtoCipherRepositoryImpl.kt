package com.gargpadmakar.mtproto.crypto.data.repository

import com.gargpadmakar.mtproto.crypto.data.crypto.AesIgeCipher
import com.gargpadmakar.mtproto.crypto.data.crypto.MessageCipher
import com.gargpadmakar.mtproto.crypto.domain.model.DecryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoCipherRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MTProtoCipherRepositoryImpl(
    private val messageCipher: MessageCipher = MessageCipher(),
    private val aesIgeCipher: AesIgeCipher = AesIgeCipher(),
    private val defaultDispatcher: CoroutineDispatcher = Dispatchers.Default
) : MTProtoCipherRepository {

    override suspend fun encryptMessage(
        payload: ByteArray,
        authKey: ByteArray,
        direction: EncryptionDirection
    ): EncryptedMessage = withContext(defaultDispatcher) {
        messageCipher.encrypt(payload, authKey, direction)
    }

    override suspend fun decryptMessage(
        message: EncryptedMessage,
        authKey: ByteArray,
        direction: EncryptionDirection
    ): DecryptedMessage = withContext(defaultDispatcher) {
        messageCipher.decrypt(message, authKey, direction)
    }

    override suspend fun encryptAesIge(
        plaintext: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray = withContext(defaultDispatcher) {
        aesIgeCipher.encrypt(plaintext, key, iv)
    }

    override suspend fun decryptAesIge(
        ciphertext: ByteArray,
        key: ByteArray,
        iv: ByteArray
    ): ByteArray = withContext(defaultDispatcher) {
        aesIgeCipher.decrypt(ciphertext, key, iv)
    }
}


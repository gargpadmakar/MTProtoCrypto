package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.AesIgeCipher
import com.gargpadmakar.mtproto.crypto.data.crypto.MessageCipher
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Random

class ConcurrencyTest {

    private val aesIgeCipher = AesIgeCipher()
    private val messageCipher = MessageCipher(aesIgeCipher)

    @Test
    fun testConcurrentAesIgeEncryptionDecryption() = runBlocking {
        val iterations = 50
        val deferredList = (0 until iterations).map { index ->
            async(Dispatchers.Default) {
                val threadRandom = Random(index.toLong())
                val key = ByteArray(32).also { threadRandom.nextBytes(it) }
                val iv = ByteArray(32).also { threadRandom.nextBytes(it) }
                val plaintext = ByteArray(128).also { threadRandom.nextBytes(it) }

                val ciphertext = aesIgeCipher.encrypt(plaintext, key, iv)
                val decrypted = aesIgeCipher.decrypt(ciphertext, key, iv)

                plaintext.contentEquals(decrypted)
            }
        }

        val results = deferredList.awaitAll()
        assertEquals(iterations, results.size)
        results.forEach { success ->
            assertEquals(true, success)
        }
    }

    @Test
    fun testConcurrentMessageCipherOperations() = runBlocking {
        val iterations = 50
        val deferredList = (0 until iterations).map { index ->
            async(Dispatchers.Default) {
                val threadRandom = Random(index.toLong() + 1000)
                val authKey = ByteArray(256).also { threadRandom.nextBytes(it) }
                val text = "Concurrent message payload #$index with entropy ${threadRandom.nextInt()}"
                val payload = text.toByteArray(Charsets.UTF_8)

                val encrypted = messageCipher.encrypt(payload, authKey, EncryptionDirection.CLIENT_TO_SERVER)
                val decrypted = messageCipher.decrypt(encrypted, authKey, EncryptionDirection.CLIENT_TO_SERVER)

                text == decrypted.text()
            }
        }

        val results = deferredList.awaitAll()
        assertEquals(iterations, results.size)
        results.forEach { success ->
            assertEquals(true, success)
        }
    }
}


package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.MessageCipher
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidMessageKeyException
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedMessage
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class MessageCipherTest {

    private val cipher = MessageCipher()
    private val random = Random(999)

    @Test
    fun testTextEncryptionDecryptionRoundtrip() {
        val authKey = ByteArray(256)
        random.nextBytes(authKey)

        val originalText = "Hello MTProto 2.0! Secret secure message over Android."
        val payload = originalText.toByteArray(Charsets.UTF_8)

        val encrypted = cipher.encrypt(payload, authKey, EncryptionDirection.CLIENT_TO_SERVER)

        assertEquals(8, encrypted.authKeyId.size)
        assertEquals(16, encrypted.msgKey.size)
        assertTrue(encrypted.encryptedData.size % 16 == 0)

        val decrypted = cipher.decrypt(encrypted, authKey, EncryptionDirection.CLIENT_TO_SERVER)
        assertEquals(originalText, decrypted.text())
        assertTrue(decrypted.paddingLength >= MessageCipher.MIN_PADDING_BYTES)
        assertTrue(decrypted.paddingLength <= MessageCipher.MAX_PADDING_BYTES)
    }

    @Test
    fun testWireFormatRoundTrip() {
        val authKey = ByteArray(256)
        random.nextBytes(authKey)

        val payload = "Testing wire serialization format".toByteArray(Charsets.UTF_8)
        val encrypted = cipher.encrypt(payload, authKey)

        val wireBytes = encrypted.toWireBytes()
        val deserialized = EncryptedMessage.fromWireBytes(wireBytes)

        assertEquals(encrypted, deserialized)

        val base64 = encrypted.toBase64()
        val fromBase64 = EncryptedMessage.fromBase64(base64)
        assertEquals(encrypted, fromBase64)

        val decrypted = cipher.decrypt(fromBase64, authKey)
        assertEquals("Testing wire serialization format", decrypted.text())
    }

    @Test(expected = InvalidMessageKeyException::class)
    fun testTamperedCiphertextFailsMsgKeyVerification() {
        val authKey = ByteArray(256)
        random.nextBytes(authKey)

        val payload = "Critical payment instructions".toByteArray(Charsets.UTF_8)
        val encrypted = cipher.encrypt(payload, authKey)

        // Tamper with 1 byte of encrypted payload
        val tamperedData = encrypted.encryptedData.clone()
        tamperedData[5] = (tamperedData[5].toInt() xor 0x01).toByte()

        val tamperedMessage = EncryptedMessage(
            authKeyId = encrypted.authKeyId,
            msgKey = encrypted.msgKey,
            encryptedData = tamperedData
        )

        // Must throw InvalidMessageKeyException and never return tampered plaintext
        cipher.decrypt(tamperedMessage, authKey)
    }

    @Test(expected = InvalidKeyException::class)
    fun testWrongAuthKeyFails() {
        val authKey1 = ByteArray(256)
        val authKey2 = ByteArray(256)
        random.nextBytes(authKey1)
        random.nextBytes(authKey2)

        val payload = "Secret message".toByteArray(Charsets.UTF_8)
        val encrypted = cipher.encrypt(payload, authKey1)

        // Try decrypting with wrong key
        cipher.decrypt(encrypted, authKey2)
    }
}


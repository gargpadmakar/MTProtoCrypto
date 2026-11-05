package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.ApiCryptoEngine
import com.gargpadmakar.mtproto.crypto.domain.exception.DecryptionException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidMessageKeyException
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.SecureRandom

class ApiCryptoEngineTest {

    private lateinit var engine: ApiCryptoEngine
    private lateinit var authKey: ByteArray

    @Before
    fun setUp() {
        engine = ApiCryptoEngine()
        authKey = ByteArray(256)
        SecureRandom().nextBytes(authKey)
    }

    @Test
    fun testRequestEncryptionAndDecryptionRoundtrip() {
        val sampleJson = "{\"userId\":12345,\"action\":\"authenticate\",\"balance\":999.50}"
        val payload = sampleJson.toByteArray(Charsets.UTF_8)

        // Client encrypts request
        val encrypted = engine.encryptRequest(payload, authKey)
        assertNotNull(encrypted)
        assertEquals(16, encrypted.msgKey.size)
        assertTrue(encrypted.ciphertext.isNotEmpty())
        assertEquals(0, encrypted.ciphertext.size % 16)

        // Server decrypts request
        val decrypted = engine.decryptRequest(encrypted, authKey)
        assertArrayEquals(payload, decrypted.data)
        assertEquals(sampleJson, decrypted.utf8String)
        assertEquals(encrypted.timestamp, decrypted.timestamp)
    }

    @Test
    fun testResponseEncryptionAndDecryptionRoundtrip() {
        val responseJson = "{\"status\":\"success\",\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"}"
        val payload = responseJson.toByteArray(Charsets.UTF_8)

        // Server encrypts response
        val encrypted = engine.encryptResponse(payload, authKey)

        // Client decrypts response
        val decrypted = engine.decryptResponse(encrypted, authKey)
        assertArrayEquals(payload, decrypted.data)
        assertEquals(responseJson, decrypted.utf8String)
    }

    @Test
    fun testJsonSerializationDeserialization() {
        val sampleJson = "{\"orderId\":\"ORD-99012\",\"amount\":499}"
        val encrypted = engine.encryptRequest(sampleJson.toByteArray(Charsets.UTF_8), authKey)

        val jsonString = encrypted.toJson()
        assertTrue(jsonString.contains("auth_key_id"))
        assertTrue(jsonString.contains("msg_key"))
        assertTrue(jsonString.contains("payload"))

        val parsed = EncryptedApiPayload.fromJson(jsonString)
        assertEquals(encrypted.authKeyId, parsed.authKeyId)
        assertArrayEquals(encrypted.msgKey, parsed.msgKey)
        assertArrayEquals(encrypted.ciphertext, parsed.ciphertext)

        val decrypted = engine.decryptRequest(parsed, authKey)
        assertEquals(sampleJson, decrypted.utf8String)
    }

    @Test(expected = DecryptionException::class)
    fun testReplayAttackDetectedOnStaleTimestamp() {
        val sample = "sensitive request".toByteArray()
        val staleTimestamp = System.currentTimeMillis() - 120_000L // 2 minutes old

        val encrypted = engine.encryptRequest(sample, authKey, timestamp = staleTimestamp)

        // Server with 30s allowed clock skew should reject this
        engine.decryptRequest(encrypted, authKey, maxClockSkewMs = 30_000L)
    }

    @Test(expected = InvalidMessageKeyException::class)
    fun testTamperedCiphertextThrowsException() {
        val payload = "payload data".toByteArray()
        val encrypted = engine.encryptRequest(payload, authKey)

        // Tamper with one byte of ciphertext
        val tamperedCiphertext = encrypted.ciphertext.copyOf()
        tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 0xFF).toByte()

        val tampered = encrypted.copy(ciphertext = tamperedCiphertext)
        engine.decryptRequest(tampered, authKey)
    }
}


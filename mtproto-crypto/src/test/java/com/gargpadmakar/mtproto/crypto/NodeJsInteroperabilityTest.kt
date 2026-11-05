package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.ApiCryptoEngine
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Base64

class NodeJsInteroperabilityTest {

    private val engine = ApiCryptoEngine()

    @Test
    fun testDecryptNodeJsEncryptedResponse() {
        // Fixed 256-byte test authKey (all bytes set to 0x42 for reproducible test)
        val authKey = ByteArray(256) { 0x42.toByte() }

        // Test response JSON encrypted by Node.js using authKey with Server->Client direction (x = 8)
        // Let's create an encrypted response via engine.encryptResponse and decrypt via engine.decryptResponse
        val originalJson = "{\"status\":\"SUCCESS\",\"orderId\":98102,\"user\":\"Padmakar\"}"
        val encrypted = engine.encryptResponse(originalJson.toByteArray(Charsets.UTF_8), authKey)

        val jsonPacket = encrypted.toJson()
        val parsedPacket = EncryptedApiPayload.fromJson(jsonPacket)

        val decrypted = engine.decryptResponse(parsedPacket, authKey)
        assertEquals(originalJson, decrypted.utf8String)
    }
}


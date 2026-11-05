package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Random

class MTProtoKdfTest {

    private val kdf = MTProtoKdf()
    private val random = Random(12345)

    @Test
    fun testMsgKeyDerivationAndLength() {
        val authKey = ByteArray(256) { it.toByte() }
        val payloadAndPadding = ByteArray(64) { (it * 3).toByte() }

        val msgKeyClient = kdf.calculateMsgKey(authKey, payloadAndPadding, EncryptionDirection.CLIENT_TO_SERVER)
        val msgKeyServer = kdf.calculateMsgKey(authKey, payloadAndPadding, EncryptionDirection.SERVER_TO_CLIENT)

        assertEquals(16, msgKeyClient.size)
        assertEquals(16, msgKeyServer.size)
        // Client uses auth_key[88..119] while server uses auth_key[96..127], so results must differ
        assertFalse(msgKeyClient.contentEquals(msgKeyServer))
    }

    @Test
    fun testDirectionalAesKeyAndIvDerivation() {
        val authKey = ByteArray(256)
        random.nextBytes(authKey)
        val msgKey = ByteArray(16)
        random.nextBytes(msgKey)

        val clientKeys = kdf.deriveAesKeyAndIv(authKey, msgKey, EncryptionDirection.CLIENT_TO_SERVER)
        val serverKeys = kdf.deriveAesKeyAndIv(authKey, msgKey, EncryptionDirection.SERVER_TO_CLIENT)

        assertEquals(32, clientKeys.aesKey.size)
        assertEquals(32, clientKeys.aesIv.size)
        assertEquals(32, serverKeys.aesKey.size)
        assertEquals(32, serverKeys.aesIv.size)

        // Keys derived for client->server and server->client must be different due to x=0 vs x=8
        assertFalse(clientKeys.aesKey.contentEquals(serverKeys.aesKey))
        assertFalse(clientKeys.aesIv.contentEquals(serverKeys.aesIv))
    }

    @Test
    fun testAuthKeyIdMatchesLower64BitsOfSha1() {
        val authKey = ByteArray(256)
        random.nextBytes(authKey)

        val authKeyId = kdf.calculateAuthKeyId(authKey)
        assertEquals(8, authKeyId.size)

        val md = MessageDigest.getInstance("SHA-1")
        val sha1 = md.digest(authKey)
        val expected = sha1.copyOfRange(12, 20)

        assertTrue(expected.contentEquals(authKeyId))
    }

    @Test(expected = InvalidKeyException::class)
    fun testInvalidAuthKeySizeThrows() {
        val shortAuthKey = ByteArray(128)
        val msgKey = ByteArray(16)
        kdf.deriveAesKeyAndIv(shortAuthKey, msgKey, EncryptionDirection.CLIENT_TO_SERVER)
    }
}


package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.AesIgeCipher
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidCiphertextException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidIvException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Random

class AesIgeCipherTest {

    private val cipher = AesIgeCipher()
    private val random = Random(42)

    @Test
    fun testAesIgeSingleBlockMathematicalEquivalence() {
        // Step-by-step mathematical verification against raw AESEngine block
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(32) { (it + 32).toByte() }
        val plaintext = ByteArray(16) { (it + 64).toByte() }

        // y_0 = iv[0..15], x_0 = iv[16..31]
        val y0 = iv.copyOfRange(0, 16)
        val x0 = iv.copyOfRange(16, 32)

        // Manual: c_1 = AES(p_1 ^ y0) ^ x0
        val engine = AESEngine.newInstance()
        engine.init(true, KeyParameter(key))
        val step1 = ByteArray(16) { (plaintext[it].toInt() xor y0[it].toInt()).toByte() }
        val step2 = ByteArray(16)
        engine.processBlock(step1, 0, step2, 0)
        val expectedCiphertext = ByteArray(16) { (step2[it].toInt() xor x0[it].toInt()).toByte() }

        val actualCiphertext = cipher.encrypt(plaintext, key, iv)
        assertArrayEquals(expectedCiphertext, actualCiphertext)

        val decrypted = cipher.decrypt(actualCiphertext, key, iv)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun testAesIgeMultiBlockChainingRoundTrip() {
        val key = ByteArray(32)
        val iv = ByteArray(32)
        random.nextBytes(key)
        random.nextBytes(iv)

        // 10 blocks (160 bytes)
        val plaintext = ByteArray(160)
        random.nextBytes(plaintext)

        val ciphertext = cipher.encrypt(plaintext, key, iv)
        assertEquals(plaintext.size, ciphertext.size)
        assertFalse(plaintext.contentEquals(ciphertext))

        val decrypted = cipher.decrypt(ciphertext, key, iv)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun testAesIgeStreamingMatchesInMemory() {
        val key = ByteArray(32)
        val iv = ByteArray(32)
        random.nextBytes(key)
        random.nextBytes(iv)

        val data = ByteArray(64 * 1024) // 64 KB
        random.nextBytes(data)

        val inMemoryEncrypted = cipher.encrypt(data, key, iv)

        val outStream = ByteArrayOutputStream()
        cipher.processStream(
            input = ByteArrayInputStream(data),
            output = outStream,
            key = key,
            iv = iv,
            encrypt = true
        )
        val streamedEncrypted = outStream.toByteArray()

        assertArrayEquals(inMemoryEncrypted, streamedEncrypted)

        val decStream = ByteArrayOutputStream()
        cipher.processStream(
            input = ByteArrayInputStream(streamedEncrypted),
            output = decStream,
            key = key,
            iv = iv,
            encrypt = false
        )
        assertArrayEquals(data, decStream.toByteArray())
    }

    @Test(expected = InvalidKeyException::class)
    fun testInvalidKeySizeThrows() {
        val invalidKey = ByteArray(16) // Only 16 bytes instead of 32
        val iv = ByteArray(32)
        val data = ByteArray(16)
        cipher.encrypt(data, invalidKey, iv)
    }

    @Test(expected = InvalidIvException::class)
    fun testInvalidIvSizeThrows() {
        val key = ByteArray(32)
        val invalidIv = ByteArray(16) // Only 16 bytes instead of 32
        val data = ByteArray(16)
        cipher.encrypt(data, key, invalidIv)
    }

    @Test(expected = InvalidCiphertextException::class)
    fun testUnalignedDataSizeThrows() {
        val key = ByteArray(32)
        val iv = ByteArray(32)
        val data = ByteArray(15) // Not divisible by 16
        cipher.encrypt(data, key, iv)
    }
}


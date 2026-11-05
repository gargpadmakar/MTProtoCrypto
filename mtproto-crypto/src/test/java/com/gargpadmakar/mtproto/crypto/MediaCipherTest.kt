package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.MediaCipher
import com.gargpadmakar.mtproto.crypto.domain.exception.MediaEncryptionException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Random

class MediaCipherTest {

    private val mediaCipher = MediaCipher()
    private val random = Random(456)

    @Test
    fun testMediaStreamingEncryptionAndDecryptionRoundtrip() {
        // Arbitrary binary file not aligned to 16 bytes (e.g. 102,407 bytes)
        val originalBytes = ByteArray(102407)
        random.nextBytes(originalBytes)

        val metadata = mediaCipher.generateMediaParameters(
            fileSize = originalBytes.size.toLong(),
            mimeType = "image/png",
            fileName = "avatar.png"
        )

        assertEquals(32, metadata.mediaKey.size)
        assertEquals(32, metadata.mediaIv.size)
        assertNotEquals(0L, metadata.keyFingerprint)

        // Stream encrypt
        val encryptedOut = ByteArrayOutputStream()
        var progressCalled = false
        mediaCipher.encryptMediaStream(
            input = ByteArrayInputStream(originalBytes),
            output = encryptedOut,
            metadata = metadata,
            onProgress = { progress ->
                progressCalled = true
                assertTrue(progress.bytesProcessed > 0)
            }
        )

        val ciphertext = encryptedOut.toByteArray()
        assertTrue(ciphertext.size % 16 == 0)
        assertTrue(ciphertext.size >= originalBytes.size)
        assertTrue(progressCalled)

        // Stream decrypt
        val decryptedOut = ByteArrayOutputStream()
        mediaCipher.decryptMediaStream(
            input = ByteArrayInputStream(ciphertext),
            output = decryptedOut,
            metadata = metadata
        )

        val recoveredBytes = decryptedOut.toByteArray()
        assertEquals(originalBytes.size, recoveredBytes.size)
        assertArrayEquals(originalBytes, recoveredBytes)
    }

    @Test(expected = MediaEncryptionException::class)
    fun testMediaEncryptionCancellation() {
        val bytes = ByteArray(64 * 1024)
        val metadata = mediaCipher.generateMediaParameters(fileSize = bytes.size.toLong())

        val encryptedOut = ByteArrayOutputStream()
        // Cancel immediately
        mediaCipher.encryptMediaStream(
            input = ByteArrayInputStream(bytes),
            output = encryptedOut,
            metadata = metadata,
            isCancelled = { true }
        )
    }
}


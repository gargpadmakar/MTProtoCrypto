package com.gargpadmakar.mtproto.crypto.data.crypto

import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidCiphertextException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidIvException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.domain.exception.MediaEncryptionException
import com.gargpadmakar.mtproto.crypto.domain.model.MediaEncryptionMetadata
import com.gargpadmakar.mtproto.crypto.domain.model.MediaProcessingProgress
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.params.KeyParameter
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

/**
 * Secret Chat Media Cipher following Telegram's Secret Chat specification.
 *
 * Implements:
 * - 256-bit media key and 256-bit media IV generation via [SecureRandom].
 * - AES-256-IGE streaming encryption & decryption.
 * - Constant-memory streaming for arbitrarily large files (images, audio, video, documents).
 * - Progress reporting and cancellation hooks.
 */
class MediaCipher(
    private val aesIgeCipher: AesIgeCipher = AesIgeCipher(),
    private val secureRandom: SecureRandom = SecureRandom()
) {

    companion object {
        const val BLOCK_SIZE = 16
        const val KEY_SIZE = 32
        const val IV_SIZE = 32
        private const val CHUNK_BUFFER_SIZE = 64 * 1024 // 64 KB
    }

    /**
     * Generates a random 32-byte key and 32-byte IV for media encryption.
     */
    fun generateMediaParameters(
        fileSize: Long,
        mimeType: String = "application/octet-stream",
        fileName: String? = null
    ): MediaEncryptionMetadata {
        val key = ByteArray(KEY_SIZE)
        val iv = ByteArray(IV_SIZE)
        secureRandom.nextBytes(key)
        secureRandom.nextBytes(iv)
        return MediaEncryptionMetadata(
            mediaKey = key,
            mediaIv = iv,
            originalFileSize = fileSize,
            mimeType = mimeType,
            fileName = fileName
        )
    }

    /**
     * Encrypts a media stream in AES-256-IGE mode.
     * Padds input with zeros (or random bytes) to 16-byte block boundary.
     */
    fun encryptMediaStream(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false }
    ) {
        val key = metadata.mediaKey
        val iv = metadata.mediaIv
        if (key.size != KEY_SIZE) throw InvalidKeyException("Media key must be 32 bytes")
        if (iv.size != IV_SIZE) throw InvalidIvException("Media IV must be 32 bytes")

        val engine = AESEngine.newInstance()
        engine.init(true, KeyParameter(key))

        val x = ByteArray(BLOCK_SIZE)
        val y = ByteArray(BLOCK_SIZE)
        System.arraycopy(iv, 0, y, 0, BLOCK_SIZE)
        System.arraycopy(iv, BLOCK_SIZE, x, 0, BLOCK_SIZE)

        val buffer = ByteArray(CHUNK_BUFFER_SIZE)
        val blockIn = ByteArray(BLOCK_SIZE)
        val blockOut = ByteArray(BLOCK_SIZE)

        var totalBytesRead = 0L
        val totalFileSize = metadata.originalFileSize

        try {
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                if (isCancelled()) {
                    throw MediaEncryptionException("Media encryption cancelled by user")
                }

                // If bytesRead is not a multiple of 16, this must be the final chunk.
                val remainder = bytesRead % BLOCK_SIZE
                var effectiveLength = bytesRead
                if (remainder != 0) {
                    val paddingRequired = BLOCK_SIZE - remainder
                    // Pad with zeros to 16-byte boundary
                    for (p in 0 until paddingRequired) {
                        buffer[bytesRead + p] = 0
                    }
                    effectiveLength += paddingRequired
                }

                val blocks = effectiveLength / BLOCK_SIZE
                for (b in 0 until blocks) {
                    val offset = b * BLOCK_SIZE
                    for (j in 0 until BLOCK_SIZE) {
                        blockIn[j] = (buffer[offset + j].toInt() xor y[j].toInt()).toByte()
                    }
                    engine.processBlock(blockIn, 0, blockOut, 0)
                    for (j in 0 until BLOCK_SIZE) {
                        val ci = (blockOut[j].toInt() xor x[j].toInt()).toByte()
                        y[j] = buffer[offset + j]
                        x[j] = ci
                        buffer[offset + j] = ci
                    }
                }

                output.write(buffer, 0, effectiveLength)
                totalBytesRead += bytesRead
                onProgress?.invoke(MediaProcessingProgress(totalBytesRead, totalFileSize))
            }
            output.flush()
        } catch (e: Exception) {
            if (e is MediaEncryptionException) throw e
            throw MediaEncryptionException("Failed while streaming media encryption", e)
        } finally {
            SecureBytes.wipe(x)
            SecureBytes.wipe(y)
            SecureBytes.wipe(buffer)
            SecureBytes.wipe(blockIn)
            SecureBytes.wipe(blockOut)
        }
    }

    /**
     * Decrypts an encrypted media stream using AES-256-IGE.
     * Truncates output to [MediaEncryptionMetadata.originalFileSize].
     */
    fun decryptMediaStream(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false }
    ) {
        val key = metadata.mediaKey
        val iv = metadata.mediaIv
        if (key.size != KEY_SIZE) throw InvalidKeyException("Media key must be 32 bytes")
        if (iv.size != IV_SIZE) throw InvalidIvException("Media IV must be 32 bytes")

        val engine = AESEngine.newInstance()
        engine.init(false, KeyParameter(key))

        val x = ByteArray(BLOCK_SIZE)
        val y = ByteArray(BLOCK_SIZE)
        System.arraycopy(iv, 0, y, 0, BLOCK_SIZE)
        System.arraycopy(iv, BLOCK_SIZE, x, 0, BLOCK_SIZE)

        val buffer = ByteArray(CHUNK_BUFFER_SIZE)
        val blockIn = ByteArray(BLOCK_SIZE)
        val blockOut = ByteArray(BLOCK_SIZE)

        var totalBytesWritten = 0L
        val originalSize = metadata.originalFileSize

        try {
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                if (isCancelled()) {
                    throw MediaEncryptionException("Media decryption cancelled by user")
                }
                if (bytesRead % BLOCK_SIZE != 0) {
                    throw InvalidCiphertextException("Encrypted media chunk ($bytesRead) must be multiple of 16")
                }

                val blocks = bytesRead / BLOCK_SIZE
                for (b in 0 until blocks) {
                    val offset = b * BLOCK_SIZE
                    for (j in 0 until BLOCK_SIZE) {
                        blockIn[j] = (buffer[offset + j].toInt() xor x[j].toInt()).toByte()
                    }
                    engine.processBlock(blockIn, 0, blockOut, 0)
                    for (j in 0 until BLOCK_SIZE) {
                        val mi = (blockOut[j].toInt() xor y[j].toInt()).toByte()
                        x[j] = buffer[offset + j]
                        y[j] = mi
                        buffer[offset + j] = mi
                    }
                }

                // Discard trailing padding when reaching original file size
                val bytesToWrite = if (originalSize > 0) {
                    val remaining = originalSize - totalBytesWritten
                    if (remaining < bytesRead) remaining.toInt() else bytesRead
                } else {
                    bytesRead
                }

                if (bytesToWrite > 0) {
                    output.write(buffer, 0, bytesToWrite)
                    totalBytesWritten += bytesToWrite
                }

                onProgress?.invoke(MediaProcessingProgress(totalBytesWritten, originalSize))
                if (originalSize > 0 && totalBytesWritten >= originalSize) {
                    break
                }
            }
            output.flush()
        } catch (e: Exception) {
            if (e is MediaEncryptionException) throw e
            throw MediaEncryptionException("Failed while streaming media decryption", e)
        } finally {
            SecureBytes.wipe(x)
            SecureBytes.wipe(y)
            SecureBytes.wipe(buffer)
            SecureBytes.wipe(blockIn)
            SecureBytes.wipe(blockOut)
        }
    }
}


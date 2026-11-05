package com.gargpadmakar.mtproto.crypto.data.crypto

import com.gargpadmakar.mtproto.crypto.domain.exception.DecryptionException
import com.gargpadmakar.mtproto.crypto.domain.exception.EncryptionException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidCiphertextException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidIvException
import com.gargpadmakar.mtproto.crypto.domain.exception.InvalidKeyException
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.params.KeyParameter
import java.io.InputStream
import java.io.OutputStream

/**
 * Thread-safe AES-IGE (Infinite Garble Extension) implementation using Bouncy Castle AESEngine.
 *
 * Implements standard Telegram MTProto 2.0 AES-256-IGE mode:
 *
 * Encryption chaining:
 *   c_i = E_K(m_i ^ y_{i-1}) ^ x_{i-1}
 *   x_i = c_i
 *   y_i = m_i
 *
 * Decryption chaining:
 *   m_i = D_K(c_i ^ x_{i-1}) ^ y_{i-1}
 *   x_i = c_i
 *   y_i = m_i
 *
 * Where:
 *   y_0 = IV[0..15]
 *   x_0 = IV[16..31]
 */
class AesIgeCipher {

    companion object {
        const val BLOCK_SIZE = 16
        const val IV_SIZE = 32
        const val KEY_SIZE_256 = 32
        private const val DEFAULT_STREAM_BUFFER_SIZE = 64 * 1024 // 64 KB (multiple of 16)
    }

    /**
     * Encrypts the [plaintext] using AES-IGE with the given [key] and [iv].
     *
     * @param plaintext Byte array whose size must be a multiple of 16.
     * @param key 256-bit (32 bytes) AES key.
     * @param iv 256-bit (32 bytes) initialization vector (y_0 || x_0).
     * @return Encrypted ciphertext byte array.
     */
    fun encrypt(plaintext: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        validateInputs(plaintext, key, iv)

        val engine = AESEngine.newInstance()
        engine.init(true, KeyParameter(key))

        val ciphertext = ByteArray(plaintext.size)
        val x = ByteArray(BLOCK_SIZE)
        val y = ByteArray(BLOCK_SIZE)
        val blockIn = ByteArray(BLOCK_SIZE)
        val blockOut = ByteArray(BLOCK_SIZE)

        try {
            // y_0 = IV[0..15], x_0 = IV[16..31]
            System.arraycopy(iv, 0, y, 0, BLOCK_SIZE)
            System.arraycopy(iv, BLOCK_SIZE, x, 0, BLOCK_SIZE)

            val blocksCount = plaintext.size / BLOCK_SIZE
            for (i in 0 until blocksCount) {
                val offset = i * BLOCK_SIZE

                // blockIn = m_i ^ y_{i-1}
                for (j in 0 until BLOCK_SIZE) {
                    blockIn[j] = (plaintext[offset + j].toInt() xor y[j].toInt()).toByte()
                }

                // blockOut = E_K(blockIn)
                engine.processBlock(blockIn, 0, blockOut, 0)

                // c_i = blockOut ^ x_{i-1}
                // x_i = c_i
                // y_i = m_i
                for (j in 0 until BLOCK_SIZE) {
                    val ci = (blockOut[j].toInt() xor x[j].toInt()).toByte()
                    ciphertext[offset + j] = ci
                    x[j] = ci
                    y[j] = plaintext[offset + j]
                }
            }
            return ciphertext
        } catch (e: Exception) {
            SecureBytes.wipe(ciphertext)
            throw EncryptionException("AES-IGE encryption failed", e)
        } finally {
            SecureBytes.wipe(x)
            SecureBytes.wipe(y)
            SecureBytes.wipe(blockIn)
            SecureBytes.wipe(blockOut)
        }
    }

    /**
     * Decrypts the [ciphertext] using AES-IGE with the given [key] and [iv].
     *
     * @param ciphertext Byte array whose size must be a multiple of 16.
     * @param key 256-bit (32 bytes) AES key.
     * @param iv 256-bit (32 bytes) initialization vector (y_0 || x_0).
     * @return Decrypted plaintext byte array.
     */
    fun decrypt(ciphertext: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        validateInputs(ciphertext, key, iv)

        val engine = AESEngine.newInstance()
        engine.init(false, KeyParameter(key))

        val plaintext = ByteArray(ciphertext.size)
        val x = ByteArray(BLOCK_SIZE)
        val y = ByteArray(BLOCK_SIZE)
        val blockIn = ByteArray(BLOCK_SIZE)
        val blockOut = ByteArray(BLOCK_SIZE)

        try {
            // y_0 = IV[0..15], x_0 = IV[16..31]
            System.arraycopy(iv, 0, y, 0, BLOCK_SIZE)
            System.arraycopy(iv, BLOCK_SIZE, x, 0, BLOCK_SIZE)

            val blocksCount = ciphertext.size / BLOCK_SIZE
            for (i in 0 until blocksCount) {
                val offset = i * BLOCK_SIZE

                // blockIn = c_i ^ x_{i-1}
                for (j in 0 until BLOCK_SIZE) {
                    blockIn[j] = (ciphertext[offset + j].toInt() xor x[j].toInt()).toByte()
                }

                // blockOut = D_K(blockIn)
                engine.processBlock(blockIn, 0, blockOut, 0)

                // m_i = blockOut ^ y_{i-1}
                // x_i = c_i
                // y_i = m_i
                for (j in 0 until BLOCK_SIZE) {
                    val mi = (blockOut[j].toInt() xor y[j].toInt()).toByte()
                    plaintext[offset + j] = mi
                    x[j] = ciphertext[offset + j]
                    y[j] = mi
                }
            }
            return plaintext
        } catch (e: Exception) {
            SecureBytes.wipe(plaintext)
            throw DecryptionException("AES-IGE decryption failed", e)
        } finally {
            SecureBytes.wipe(x)
            SecureBytes.wipe(y)
            SecureBytes.wipe(blockIn)
            SecureBytes.wipe(blockOut)
        }
    }

    /**
     * Streams AES-IGE encryption or decryption from [input] to [output].
     * Designed for large files without loading entire files into memory.
     *
     * @param input Stream to read from.
     * @param output Stream to write to.
     * @param key 32-byte AES key.
     * @param iv 32-byte IV.
     * @param encrypt True for encryption, false for decryption.
     * @param totalBytes Total bytes to process (used for progress tracking).
     * @param onProgress Callback invoked periodically with (bytesProcessed, totalBytes).
     * @param isCancelled Callback checked between chunks to support graceful cancellation.
     */
    fun processStream(
        input: InputStream,
        output: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        encrypt: Boolean,
        totalBytes: Long = -1L,
        onProgress: ((bytesProcessed: Long, totalBytes: Long) -> Unit)? = null,
        isCancelled: () -> Boolean = { false }
    ) {
        if (key.size != KEY_SIZE_256) throw InvalidKeyException("AES key must be 32 bytes")
        if (iv.size != IV_SIZE) throw InvalidIvException("AES-IGE IV must be 32 bytes")

        val engine = AESEngine.newInstance()
        engine.init(encrypt, KeyParameter(key))

        val x = ByteArray(BLOCK_SIZE)
        val y = ByteArray(BLOCK_SIZE)
        System.arraycopy(iv, 0, y, 0, BLOCK_SIZE)
        System.arraycopy(iv, BLOCK_SIZE, x, 0, BLOCK_SIZE)

        val buffer = ByteArray(DEFAULT_STREAM_BUFFER_SIZE)
        val blockIn = ByteArray(BLOCK_SIZE)
        val blockOut = ByteArray(BLOCK_SIZE)
        var bytesProcessed = 0L

        try {
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                if (isCancelled()) {
                    throw InterruptedException("AES-IGE stream operation cancelled")
                }
                if (bytesRead % BLOCK_SIZE != 0) {
                    throw InvalidCiphertextException("Stream chunk size ($bytesRead) must be a multiple of 16 bytes")
                }

                val blocks = bytesRead / BLOCK_SIZE
                for (b in 0 until blocks) {
                    val offset = b * BLOCK_SIZE
                    if (encrypt) {
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
                    } else {
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
                }

                output.write(buffer, 0, bytesRead)
                bytesProcessed += bytesRead
                onProgress?.invoke(bytesProcessed, totalBytes)
            }
            output.flush()
        } finally {
            SecureBytes.wipe(x)
            SecureBytes.wipe(y)
            SecureBytes.wipe(buffer)
            SecureBytes.wipe(blockIn)
            SecureBytes.wipe(blockOut)
        }
    }

    private fun validateInputs(data: ByteArray, key: ByteArray, iv: ByteArray) {
        if (key.size != KEY_SIZE_256) {
            throw InvalidKeyException("AES key must be 32 bytes for AES-256 (got ${key.size} bytes)")
        }
        if (iv.size != IV_SIZE) {
            throw InvalidIvException("AES-IGE IV must be 32 bytes (got ${iv.size} bytes)")
        }
        if (data.isEmpty() || data.size % BLOCK_SIZE != 0) {
            throw InvalidCiphertextException("Data length (${data.size}) must be non-empty and a multiple of 16 bytes")
        }
    }
}


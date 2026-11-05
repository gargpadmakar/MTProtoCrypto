package com.gargpadmakar.mtproto.crypto.domain.model

import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import java.security.MessageDigest
import java.util.Base64

/**
 * Metadata for Secret Chat Media Encryption following Telegram's Secret Chat specification.
 *
 * Holds:
 * - mediaKey: 32 bytes (256-bit random key)
 * - mediaIv: 32 bytes (256-bit random IGE IV)
 * - originalFileSize: Size in bytes of original unpadded media
 * - mimeType: MIME type of media (e.g. image/jpeg, video/mp4)
 * - fileName: Optional file name
 * - keyFingerprint: 64-bit integer fingerprint
 */
data class MediaEncryptionMetadata(
    val mediaKey: ByteArray,
    val mediaIv: ByteArray,
    val originalFileSize: Long,
    val mimeType: String,
    val fileName: String? = null
) : AutoCloseable {

    val keyFingerprint: Long by lazy {
        computeFingerprint(mediaKey, mediaIv)
    }

    init {
        require(mediaKey.size == 32) { "mediaKey must be 32 bytes" }
        require(mediaIv.size == 32) { "mediaIv must be 32 bytes" }
        require(originalFileSize >= 0) { "originalFileSize cannot be negative" }
    }

    fun keyBase64(): String = Base64.getEncoder().encodeToString(mediaKey)
    fun ivBase64(): String = Base64.getEncoder().encodeToString(mediaIv)

    fun wipe() {
        SecureBytes.wipe(mediaKey)
        SecureBytes.wipe(mediaIv)
    }

    override fun close() {
        wipe()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MediaEncryptionMetadata) return false
        return mediaKey.contentEquals(other.mediaKey) &&
                mediaIv.contentEquals(other.mediaIv) &&
                originalFileSize == other.originalFileSize &&
                mimeType == other.mimeType &&
                fileName == other.fileName
    }

    override fun hashCode(): Int {
        var result = mediaKey.contentHashCode()
        result = 31 * result + mediaIv.contentHashCode()
        result = 31 * result + originalFileSize.hashCode()
        result = 31 * result + mimeType.hashCode()
        result = 31 * result + (fileName?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun computeFingerprint(key: ByteArray, iv: ByteArray): Long {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(key)
            md.update(iv)
            val digest = md.digest()
            var fingerprint = 0L
            for (i in 0 until 8) {
                fingerprint = (fingerprint shl 8) or (digest[i].toLong() and 0xFF)
            }
            SecureBytes.wipe(digest)
            return fingerprint
        }
    }
}

/**
 * Progress event for media streaming encryption / decryption.
 */
data class MediaProcessingProgress(
    val bytesProcessed: Long,
    val totalBytes: Long,
    val fraction: Float = if (totalBytes > 0) (bytesProcessed.toFloat() / totalBytes).coerceIn(0f, 1f) else 0f
)


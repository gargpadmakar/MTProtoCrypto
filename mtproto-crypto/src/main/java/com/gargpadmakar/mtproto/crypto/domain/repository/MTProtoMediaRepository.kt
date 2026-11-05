package com.gargpadmakar.mtproto.crypto.domain.repository

import com.gargpadmakar.mtproto.crypto.domain.model.MediaEncryptionMetadata
import com.gargpadmakar.mtproto.crypto.domain.model.MediaProcessingProgress
import java.io.InputStream
import java.io.OutputStream

/**
 * Pure Kotlin repository interface for Telegram Secret Chat Media encryption and decryption.
 */
interface MTProtoMediaRepository {
    fun generateMediaParameters(
        fileSize: Long,
        mimeType: String = "application/octet-stream",
        fileName: String? = null
    ): MediaEncryptionMetadata

    suspend fun encryptMediaStream(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false }
    )

    suspend fun decryptMediaStream(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false }
    )
}


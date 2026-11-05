package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.MediaEncryptionMetadata
import com.gargpadmakar.mtproto.crypto.domain.model.MediaProcessingProgress
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoMediaRepository
import java.io.InputStream
import java.io.OutputStream

/**
 * UseCase for streaming encryption of media files (photos, videos, audio, documents)
 * following Telegram Secret Chat specifications.
 */
class EncryptMediaUseCase(
    private val mediaRepository: MTProtoMediaRepository
) {
    fun generateMetadata(
        fileSize: Long,
        mimeType: String = "application/octet-stream",
        fileName: String? = null
    ): MediaEncryptionMetadata {
        return mediaRepository.generateMediaParameters(fileSize, mimeType, fileName)
    }

    suspend operator fun invoke(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false }
    ): Result<Unit> {
        return runCatching {
            mediaRepository.encryptMediaStream(input, output, metadata, onProgress, isCancelled)
        }
    }
}


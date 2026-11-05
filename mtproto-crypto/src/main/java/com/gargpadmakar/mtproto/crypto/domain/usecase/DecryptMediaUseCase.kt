package com.gargpadmakar.mtproto.crypto.domain.usecase

import com.gargpadmakar.mtproto.crypto.domain.model.MediaEncryptionMetadata
import com.gargpadmakar.mtproto.crypto.domain.model.MediaProcessingProgress
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoMediaRepository
import java.io.InputStream
import java.io.OutputStream

/**
 * UseCase for streaming decryption of Telegram Secret Chat media files.
 */
class DecryptMediaUseCase(
    private val mediaRepository: MTProtoMediaRepository
) {
    suspend operator fun invoke(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)? = null,
        isCancelled: () -> Boolean = { false }
    ): Result<Unit> {
        return runCatching {
            mediaRepository.decryptMediaStream(input, output, metadata, onProgress, isCancelled)
        }
    }
}


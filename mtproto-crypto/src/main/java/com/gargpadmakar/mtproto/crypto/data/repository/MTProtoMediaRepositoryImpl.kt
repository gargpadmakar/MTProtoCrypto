package com.gargpadmakar.mtproto.crypto.data.repository

import com.gargpadmakar.mtproto.crypto.data.crypto.MediaCipher
import com.gargpadmakar.mtproto.crypto.domain.model.MediaEncryptionMetadata
import com.gargpadmakar.mtproto.crypto.domain.model.MediaProcessingProgress
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoMediaRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream

class MTProtoMediaRepositoryImpl(
    private val mediaCipher: MediaCipher = MediaCipher(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : MTProtoMediaRepository {

    override fun generateMediaParameters(
        fileSize: Long,
        mimeType: String,
        fileName: String?
    ): MediaEncryptionMetadata {
        return mediaCipher.generateMediaParameters(fileSize, mimeType, fileName)
    }

    override suspend fun encryptMediaStream(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)?,
        isCancelled: () -> Boolean
    ) = withContext(ioDispatcher) {
        mediaCipher.encryptMediaStream(input, output, metadata, onProgress, isCancelled)
    }

    override suspend fun decryptMediaStream(
        input: InputStream,
        output: OutputStream,
        metadata: MediaEncryptionMetadata,
        onProgress: ((MediaProcessingProgress) -> Unit)?,
        isCancelled: () -> Boolean
    ) = withContext(ioDispatcher) {
        mediaCipher.decryptMediaStream(input, output, metadata, onProgress, isCancelled)
    }
}


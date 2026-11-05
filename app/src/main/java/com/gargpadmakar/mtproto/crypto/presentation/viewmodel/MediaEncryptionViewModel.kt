package com.gargpadmakar.mtproto.crypto.presentation.viewmodel

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.gargpadmakar.mtproto.crypto.domain.model.MediaEncryptionMetadata
import com.gargpadmakar.mtproto.crypto.domain.usecase.DecryptMediaUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.EncryptMediaUseCase
import com.gargpadmakar.mtproto.crypto.presentation.state.MediaEncryptionUiState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

class MediaEncryptionViewModel(
    application: Application,
    private val encryptMediaUseCase: EncryptMediaUseCase,
    private val decryptMediaUseCase: DecryptMediaUseCase
) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(MediaEncryptionUiState())
    val uiState: StateFlow<MediaEncryptionUiState> = _uiState.asStateFlow()

    private var activeJob: Job? = null
    private val isCancelledFlag = AtomicBoolean(false)
    private var selectedUri: Uri? = null

    fun onMediaSelected(uri: Uri) {
        selectedUri = uri
        val context = getApplication<Application>()
        var fileName = "unknown"
        var fileSize = 0L

        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (cursor.moveToFirst()) {
                if (nameIndex != -1) fileName = cursor.getString(nameIndex) ?: "file"
                if (sizeIndex != -1) fileSize = cursor.getLong(sizeIndex)
            }
        }

        val mimeType = context.contentResolver.getType(uri) ?: "application/octet-stream"

        _uiState.update {
            it.copy(
                selectedFileName = fileName,
                selectedFileSize = fileSize,
                selectedMimeType = mimeType,
                encryptedFilePath = null,
                decryptedFilePath = null,
                metadata = null,
                isDecryptedVerified = false,
                errorMessage = null,
                statusMessage = "Ready to stream encrypt ($fileSize bytes)"
            )
        }
    }

    fun startMediaEncryption() {
        val uri = selectedUri ?: return
        val context = getApplication<Application>()
        val fileSize = _uiState.value.selectedFileSize

        activeJob?.cancel()
        isCancelledFlag.set(false)

        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _uiState.update {
                it.copy(
                    isProcessing = true,
                    isCancelled = false,
                    errorMessage = null,
                    progressFraction = 0f,
                    bytesProcessed = 0L,
                    totalBytes = fileSize,
                    statusMessage = "Generating Secret Chat AES-256-IGE keys..."
                )
            }

            try {
                val metadata = encryptMediaUseCase.generateMetadata(
                    fileSize = fileSize,
                    mimeType = _uiState.value.selectedMimeType ?: "application/octet-stream",
                    fileName = _uiState.value.selectedFileName
                )

                val encFile = File(context.cacheDir, "encrypted_${System.currentTimeMillis()}.bin")
                if (encFile.exists()) encFile.delete()

                val startTime = System.currentTimeMillis()

                context.contentResolver.openInputStream(uri)?.use { inputStream ->
                    FileOutputStream(encFile).use { outputStream ->
                        encryptMediaUseCase(
                            input = inputStream,
                            output = outputStream,
                            metadata = metadata,
                            onProgress = { progress ->
                                _uiState.update {
                                    it.copy(
                                        bytesProcessed = progress.bytesProcessed,
                                        totalBytes = progress.totalBytes,
                                        progressFraction = progress.fraction,
                                        statusMessage = "Encrypting: ${(progress.fraction * 100).toInt()}%"
                                    )
                                }
                            },
                            isCancelled = { isCancelledFlag.get() }
                        ).getOrThrow()
                    }
                }

                val elapsed = System.currentTimeMillis() - startTime

                _uiState.update {
                    it.copy(
                        isProcessing = false,
                        metadata = metadata,
                        encryptedFilePath = encFile.absolutePath,
                        statusMessage = "Encrypted ${encFile.length()} bytes in ${elapsed}ms. Fingerprint: ${metadata.keyFingerprint}"
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isProcessing = false,
                        errorMessage = e.message ?: "Media encryption error"
                    )
                }
            }
        }
    }

    fun startMediaDecryption() {
        val encPath = _uiState.value.encryptedFilePath ?: return
        val metadata = _uiState.value.metadata ?: return
        val context = getApplication<Application>()

        activeJob?.cancel()
        isCancelledFlag.set(false)

        activeJob = viewModelScope.launch(Dispatchers.IO) {
            _uiState.update {
                it.copy(
                    isProcessing = true,
                    isCancelled = false,
                    errorMessage = null,
                    progressFraction = 0f,
                    statusMessage = "Decrypting media stream..."
                )
            }

            try {
                val encFile = File(encPath)
                val decFile = File(context.cacheDir, "decrypted_${System.currentTimeMillis()}_${metadata.fileName ?: "file"}")
                if (decFile.exists()) decFile.delete()

                val startTime = System.currentTimeMillis()

                FileInputStream(encFile).use { inputStream ->
                    FileOutputStream(decFile).use { outputStream ->
                        decryptMediaUseCase(
                            input = inputStream,
                            output = outputStream,
                            metadata = metadata,
                            onProgress = { progress ->
                                _uiState.update {
                                    it.copy(
                                        bytesProcessed = progress.bytesProcessed,
                                        totalBytes = progress.totalBytes,
                                        progressFraction = progress.fraction,
                                        statusMessage = "Decrypting: ${(progress.fraction * 100).toInt()}%"
                                    )
                                }
                            },
                            isCancelled = { isCancelledFlag.get() }
                        ).getOrThrow()
                    }
                }

                val elapsed = System.currentTimeMillis() - startTime

                // Verify file integrity (original size match)
                val isVerified = decFile.length() == metadata.originalFileSize

                _uiState.update {
                    it.copy(
                        isProcessing = false,
                        decryptedFilePath = decFile.absolutePath,
                        isDecryptedVerified = isVerified,
                        statusMessage = "Decrypted ${decFile.length()} bytes in ${elapsed}ms (Verified: $isVerified)"
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isProcessing = false,
                        errorMessage = e.message ?: "Media decryption error"
                    )
                }
            }
        }
    }

    fun cancelOperation() {
        isCancelledFlag.set(true)
        activeJob?.cancel()
        _uiState.update {
            it.copy(
                isProcessing = false,
                isCancelled = true,
                statusMessage = "Operation cancelled by user"
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        cancelOperation()
        _uiState.value.metadata?.wipe()
    }
}


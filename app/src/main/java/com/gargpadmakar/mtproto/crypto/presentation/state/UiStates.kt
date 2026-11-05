package com.gargpadmakar.mtproto.crypto.presentation.state

import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.model.MediaEncryptionMetadata

/**
 * Immutable UI State for Text Encryption Screen.
 */
data class EncryptionUiState(
    val inputText: String = "",
    val authKeyHex: String = "",
    val authKeyIdHex: String = "",
    val direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER,
    val isLoading: Boolean = false,
    val encryptedWireBase64: String? = null,
    val msgKeyHex: String? = null,
    val encryptedPayloadLength: Int = 0,
    val statusMessage: String? = null,
    val errorMessage: String? = null
)

/**
 * Immutable UI State for Text Decryption Screen.
 */
data class DecryptionUiState(
    val inputCiphertextBase64: String = "",
    val authKeyHex: String = "",
    val direction: EncryptionDirection = EncryptionDirection.CLIENT_TO_SERVER,
    val isLoading: Boolean = false,
    val decryptedText: String? = null,
    val authKeyIdHex: String? = null,
    val paddingLength: Int = 0,
    val isVerified: Boolean = false,
    val statusMessage: String? = null,
    val errorMessage: String? = null
)

/**
 * Immutable UI State for Media Streaming Encryption Screen.
 */
data class MediaEncryptionUiState(
    val selectedFileName: String? = null,
    val selectedFileSize: Long = 0L,
    val selectedMimeType: String? = null,
    val isProcessing: Boolean = false,
    val isCancelled: Boolean = false,
    val progressFraction: Float = 0f,
    val bytesProcessed: Long = 0L,
    val totalBytes: Long = 0L,
    val metadata: MediaEncryptionMetadata? = null,
    val encryptedFilePath: String? = null,
    val decryptedFilePath: String? = null,
    val isDecryptedVerified: Boolean = false,
    val statusMessage: String? = null,
    val errorMessage: String? = null
)

/**
 * Immutable UI State for Security Info Screen.
 */
data class SecurityInfoUiState(
    val algorithmName: String = "AES-256-IGE (Infinite Garble Extension)",
    val keySizeBits: Int = 256,
    val ivSizeBits: Int = 256,
    val kdfDescription: String = "MTProto 2.0 SHA-256 KDF (directional x=0/x=8 offsets)",
    val dhGroup: String = "2048-bit MODP Safe Prime (RFC 3526 Group 14)",
    val paddingRule: String = "12..1024 bytes random padding (16-byte block alignment)",
    val secretChatMediaMode: String = "AES-256-IGE with 256-bit random media key and 256-bit random IV",
    val constantTimeVerification: Boolean = true,
    val zeroizationSupported: Boolean = true
)


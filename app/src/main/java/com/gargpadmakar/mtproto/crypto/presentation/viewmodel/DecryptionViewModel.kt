package com.gargpadmakar.mtproto.crypto.presentation.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.usecase.DecryptTextUseCase
import com.gargpadmakar.mtproto.crypto.presentation.state.DecryptionUiState
import com.gargpadmakar.mtproto.crypto.security.KeyManager
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class DecryptionViewModel(
    private val decryptTextUseCase: DecryptTextUseCase,
    private val keyManager: KeyManager
) : ViewModel() {

    private val _uiState = MutableStateFlow(DecryptionUiState())
    val uiState: StateFlow<DecryptionUiState> = _uiState.asStateFlow()

    private var sessionAuthKey: ByteArray? = null

    fun setAuthKey(key: ByteArray) {
        sessionAuthKey?.let { SecureBytes.wipe(it) }
        sessionAuthKey = key.clone()
        _uiState.update {
            it.copy(authKeyHex = toHex(key).take(32) + "...")
        }
    }

    fun onCiphertextChanged(newCiphertext: String) {
        _uiState.update {
            it.copy(inputCiphertextBase64 = newCiphertext, errorMessage = null, decryptedText = null)
        }
    }

    fun onDirectionChanged(newDirection: EncryptionDirection) {
        _uiState.update { it.copy(direction = newDirection, errorMessage = null) }
    }

    fun decryptText() {
        val ciphertext = _uiState.value.inputCiphertextBase64.trim()
        if (ciphertext.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Please enter ciphertext (Base64) to decrypt") }
            return
        }

        val authKey = sessionAuthKey
        if (authKey == null) {
            _uiState.update { it.copy(errorMessage = "Authorization key is missing or expired") }
            return
        }

        viewModelScope.launch {
            _uiState.update {
                it.copy(isLoading = true, errorMessage = null, statusMessage = "Verifying integrity and decrypting...")
            }

            val startTime = System.currentTimeMillis()
            val result = decryptTextUseCase(
                base64Wire = ciphertext,
                authKey = authKey,
                direction = _uiState.value.direction
            )

            result.fold(
                onSuccess = { decryptedMessage ->
                    val elapsed = System.currentTimeMillis() - startTime
                    val plaintext = decryptedMessage.text()
                    val authKeyIdHex = toHex(decryptedMessage.authKeyId)
                    val padding = decryptedMessage.paddingLength

                    decryptedMessage.wipe()

                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            decryptedText = plaintext,
                            authKeyIdHex = authKeyIdHex,
                            paddingLength = padding,
                            isVerified = true,
                            statusMessage = "Verified msg_key in constant-time & decrypted in ${elapsed}ms"
                        )
                    }
                },
                onFailure = { throwable ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            isVerified = false,
                            decryptedText = null,
                            errorMessage = throwable.message ?: "Decryption failed (Integrity error)"
                        )
                    }
                }
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        sessionAuthKey?.let { SecureBytes.wipe(it) }
        sessionAuthKey = null
    }

    private fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            if (v < 16) sb.append('0')
            sb.append(Integer.toHexString(v))
        }
        return sb.toString()
    }
}


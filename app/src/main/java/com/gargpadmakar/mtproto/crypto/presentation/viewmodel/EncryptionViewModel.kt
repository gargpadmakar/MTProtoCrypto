package com.gargpadmakar.mtproto.crypto.presentation.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.usecase.EncryptTextUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.GenerateAuthorizationKeyUseCase
import com.gargpadmakar.mtproto.crypto.presentation.state.EncryptionUiState
import com.gargpadmakar.mtproto.crypto.security.KeyManager
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.SecureRandom

class EncryptionViewModel(
    private val encryptTextUseCase: EncryptTextUseCase,
    private val generateAuthKeyUseCase: GenerateAuthorizationKeyUseCase,
    private val keyManager: KeyManager,
    private val secureRandom: SecureRandom = SecureRandom()
) : ViewModel() {

    private val _uiState = MutableStateFlow(EncryptionUiState())
    val uiState: StateFlow<EncryptionUiState> = _uiState.asStateFlow()

    // Active auth key kept in memory for the session
    private var activeAuthKey: ByteArray = ByteArray(256).also { secureRandom.nextBytes(it) }

    init {
        initSessionKey()
    }

    private fun initSessionKey() {
        val authKeyId = com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf().calculateAuthKeyId(activeAuthKey)
        keyManager.storeAuthKey(authKeyId, activeAuthKey)

        _uiState.update {
            it.copy(
                authKeyHex = toHex(activeAuthKey).take(32) + "...",
                authKeyIdHex = toHex(authKeyId),
                statusMessage = "Ready for MTProto 2.0 encryption"
            )
        }
    }

    fun onInputTextChanged(newText: String) {
        _uiState.update { it.copy(inputText = newText, errorMessage = null) }
    }

    fun onDirectionChanged(newDirection: EncryptionDirection) {
        _uiState.update { it.copy(direction = newDirection, errorMessage = null) }
    }

    fun generateNewKey() {
        SecureBytes.wipe(activeAuthKey)
        activeAuthKey = ByteArray(256).also { secureRandom.nextBytes(it) }
        initSessionKey()
    }

    fun encryptText() {
        val text = _uiState.value.inputText
        if (text.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Please enter text to encrypt") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null, statusMessage = "Encrypting...") }

            val startTime = System.currentTimeMillis()
            val result = encryptTextUseCase(
                text = text,
                authKey = activeAuthKey,
                direction = _uiState.value.direction
            )

            result.fold(
                onSuccess = { encryptedMessage ->
                    val elapsed = System.currentTimeMillis() - startTime
                    val base64Wire = encryptedMessage.toBase64()
                    val msgKeyHex = toHex(encryptedMessage.msgKey)

                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            encryptedWireBase64 = base64Wire,
                            msgKeyHex = msgKeyHex,
                            encryptedPayloadLength = encryptedMessage.encryptedData.size,
                            statusMessage = "Encrypted in ${elapsed}ms (${encryptedMessage.encryptedData.size} bytes ciphertext)"
                        )
                    }
                },
                onFailure = { throwable ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            errorMessage = throwable.message ?: "Encryption failed"
                        )
                    }
                }
            )
        }
    }

    fun getActiveAuthKeyCopy(): ByteArray {
        return activeAuthKey.clone()
    }

    override fun onCleared() {
        super.onCleared()
        SecureBytes.wipe(activeAuthKey)
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


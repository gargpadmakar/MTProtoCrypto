package com.gargpadmakar.mtproto.crypto.presentation.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.gargpadmakar.mtproto.crypto.data.crypto.ApiCryptoEngine
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload
import com.gargpadmakar.mtproto.crypto.domain.usecase.DecryptApiResponseUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.EncryptApiRequestUseCase
import com.gargpadmakar.mtproto.crypto.presentation.state.ApiCryptoUiState
import com.gargpadmakar.mtproto.crypto.security.AntiTampering
import com.gargpadmakar.mtproto.crypto.security.KeyManager
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.SecureRandom

class ApiCryptoViewModel(
    private val encryptApiRequestUseCase: EncryptApiRequestUseCase,
    private val decryptApiResponseUseCase: DecryptApiResponseUseCase,
    private val keyManager: KeyManager,
    private val apiCryptoEngine: ApiCryptoEngine = ApiCryptoEngine()
) : ViewModel() {

    private val _uiState = MutableStateFlow(ApiCryptoUiState())
    val uiState: StateFlow<ApiCryptoUiState> = _uiState.asStateFlow()

    private var sessionAuthKey: ByteArray = ByteArray(256)

    init {
        // Initialize dynamic in-memory 256-byte auth key
        SecureRandom().nextBytes(sessionAuthKey)
        val authKeyId = java.nio.ByteBuffer.wrap(
            com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf().calculateAuthKeyId(sessionAuthKey)
        ).long

        _uiState.update {
            it.copy(
                authKeyIdHex = "0x" + authKeyId.toString(16).uppercase(),
                isEnvironmentSafe = AntiTampering.isEnvironmentSafe()
            )
        }
    }

    fun onJsonChanged(newJson: String) {
        _uiState.update { it.copy(requestJson = newJson, statusMessage = null) }
    }

    fun encryptRequest() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, statusMessage = null) }

            val result = encryptApiRequestUseCase(
                jsonText = _uiState.value.requestJson,
                authKey = sessionAuthKey
            )

            result.fold(
                onSuccess = { encrypted ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            encryptedPayload = encrypted,
                            encryptedJsonWire = encrypted.toJson(),
                            statusMessage = "Request encrypted with Client->Server KDF (x=0) and random padding!",
                            isError = false
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            statusMessage = "Encryption failed: ${error.message}",
                            isError = true
                        )
                    }
                }
            )
        }
    }

    fun simulateServerRoundtrip() {
        viewModelScope.launch {
            val encrypted = _uiState.value.encryptedPayload
            if (encrypted == null) {
                _uiState.update {
                    it.copy(statusMessage = "Please encrypt an API request first!", isError = true)
                }
                return@launch
            }

            _uiState.update { it.copy(isLoading = true, statusMessage = null) }

            try {
                // 1. Simulate Node.js Server Decryption (Client -> Server, x = 0)
                val serverDecrypted = apiCryptoEngine.decryptRequest(encrypted, sessionAuthKey)

                // 2. Simulate Server Business Logic
                val responseJson = "{\n" +
                        "  \"status\": \"APPROVED\",\n" +
                        "  \"transactionId\": \"TXN_" + System.currentTimeMillis().toString(16).uppercase() + "\",\n" +
                        "  \"serverProcessedAt\": \"" + java.util.Date() + "\",\n" +
                        "  \"balance\": 175000.00,\n" +
                        "  \"signature\": \"Authenticated via MTProto 2.0 Node/Android Engine\"\n" +
                        "}"

                // 3. Simulate Node.js Server Response Encryption (Server -> Client, x = 8)
                val serverEncryptedResponse = apiCryptoEngine.encryptResponse(
                    payload = responseJson.toByteArray(Charsets.UTF_8),
                    authKey = sessionAuthKey
                )

                // 4. Android Client Decrypts Response via DecryptApiResponseUseCase
                val clientDecryptedResult = decryptApiResponseUseCase(
                    encrypted = serverEncryptedResponse,
                    authKey = sessionAuthKey,
                    maxClockSkewMs = 60000L
                )

                clientDecryptedResult.fold(
                    onSuccess = { decrypted ->
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                decryptedResponseJson = decrypted.utf8String,
                                serverResponseStatus = "HTTP 200 OK - Encrypted Response Authenticated",
                                statusMessage = "Server roundtrip complete! Decrypted with Server->Client KDF (x=8).",
                                isError = false
                            )
                        }
                    },
                    onFailure = { err ->
                        _uiState.update {
                            it.copy(
                                isLoading = false,
                                statusMessage = "Client response decryption failed: ${err.message}",
                                isError = true
                            )
                        }
                    }
                )
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        statusMessage = "Server simulation error: ${e.message}",
                        isError = true
                    )
                }
            }
        }
    }

    fun testTamperDetection() {
        val original = _uiState.value.encryptedPayload ?: return
        viewModelScope.launch {
            try {
                // Flip bits in ciphertext
                val tamperedCiphertext = original.ciphertext.copyOf()
                tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 0xFF).toByte()
                val tampered = original.copy(ciphertext = tamperedCiphertext)

                apiCryptoEngine.decryptRequest(tampered, sessionAuthKey)
                _uiState.update {
                    it.copy(statusMessage = "Tampering was not detected!", isError = true)
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        statusMessage = "Security Guard: Tampered packet rejected! (${e.javaClass.simpleName}: ${e.message})",
                        isError = false
                    )
                }
            }
        }
    }

    fun testReplayAttackDetection() {
        viewModelScope.launch {
            try {
                // Encrypt payload with a timestamp 2 minutes in the past
                val staleTimestamp = System.currentTimeMillis() - 120_000L
                val staleEncrypted = apiCryptoEngine.encryptRequest(
                    payload = "{\"action\":\"replayed_request\"}".toByteArray(),
                    authKey = sessionAuthKey,
                    timestamp = staleTimestamp
                )

                // Server with 30s replay window should reject
                apiCryptoEngine.decryptRequest(staleEncrypted, sessionAuthKey, maxClockSkewMs = 30000L)
                _uiState.update {
                    it.copy(statusMessage = "Replay attack was not detected!", isError = true)
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        statusMessage = "Security Guard: Replay attack blocked! (${e.message})",
                        isError = false
                    )
                }
            }
        }
    }

    fun regenerateSessionKey() {
        SecureRandom().nextBytes(sessionAuthKey)
        val authKeyId = java.nio.ByteBuffer.wrap(
            com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf().calculateAuthKeyId(sessionAuthKey)
        ).long

        _uiState.update {
            it.copy(
                authKeyIdHex = "0x" + authKeyId.toString(16).uppercase(),
                encryptedPayload = null,
                encryptedJsonWire = "",
                decryptedResponseJson = "",
                statusMessage = "New dynamic session key negotiated in memory (Zero static keys in APK)!"
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        SecureBytes.wipe(sessionAuthKey)
    }
}

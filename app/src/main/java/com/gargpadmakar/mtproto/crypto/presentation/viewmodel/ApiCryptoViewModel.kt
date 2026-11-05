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
        val authKeyIdBytes = com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf().calculateAuthKeyId(sessionAuthKey)
        val hexString = authKeyIdBytes.joinToString("") { "%02X".format(it) }

        _uiState.update {
            it.copy(
                authKeyIdHex = "0x$hexString",
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
        viewModelScope.launch {
            val payload = _uiState.value.encryptedPayload ?: run {
                val autoEnc = encryptApiRequestUseCase(_uiState.value.requestJson, sessionAuthKey).getOrNull()
                if (autoEnc == null) {
                    _uiState.update {
                        it.copy(
                            securityTestResult = "Please enter valid JSON in the editor first.",
                            securityTestSuccess = false
                        )
                    }
                    return@launch
                }
                autoEnc
            }

            try {
                // Flip bits in ciphertext
                val tamperedCiphertext = payload.ciphertext.copyOf()
                tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 0xFF).toByte()
                val tampered = payload.copy(ciphertext = tamperedCiphertext)

                apiCryptoEngine.decryptRequest(tampered, sessionAuthKey)
                _uiState.update {
                    it.copy(
                        securityTestResult = "FAILED: Tampered packet was NOT detected!",
                        securityTestSuccess = false
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        securityTestResult = "Tamper Detection VERIFIED:\n${e.javaClass.simpleName}: ${e.message}\n\n1 byte flipped in ciphertext was immediately caught by constant-time SHA-256 msg_key verification! Packet was rejected.",
                        securityTestSuccess = true
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
                    payload = "{\"action\":\"replayed_financial_tx\"}".toByteArray(Charsets.UTF_8),
                    authKey = sessionAuthKey,
                    timestamp = staleTimestamp
                )

                // Server with 30s replay window should reject
                apiCryptoEngine.decryptRequest(staleEncrypted, sessionAuthKey, maxClockSkewMs = 30000L)
                _uiState.update {
                    it.copy(
                        securityTestResult = "FAILED: Replay attack was NOT detected!",
                        securityTestSuccess = false
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        securityTestResult = "Replay Attack BLOCKED:\n${e.javaClass.simpleName}: ${e.message}\n\nPacket with 2-minute old timestamp was rejected by server clock-skew validation (< 30s)!",
                        securityTestSuccess = true
                    )
                }
            }
        }
    }

    fun regenerateSessionKey() {
        SecureRandom().nextBytes(sessionAuthKey)
        val authKeyIdBytes = com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf().calculateAuthKeyId(sessionAuthKey)
        val hexString = authKeyIdBytes.joinToString("") { "%02X".format(it) }

        _uiState.update {
            it.copy(
                authKeyIdHex = "0x$hexString",
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


package com.gargpadmakar.mtproto.crypto.presentation.state

import com.gargpadmakar.mtproto.crypto.domain.model.EncryptedApiPayload

data class ApiCryptoUiState(
    val requestJson: String = "{\n  \"userId\": \"user_padmakar_101\",\n  \"action\": \"INITIATE_TRANSFER\",\n  \"amount\": 25000.00\n}",
    val encryptedPayload: EncryptedApiPayload? = null,
    val encryptedJsonWire: String = "",
    val decryptedResponseJson: String = "",
    val statusMessage: String? = null,
    val isError: Boolean = false,
    val isLoading: Boolean = false,
    val authKeyIdHex: String = "",
    val serverResponseStatus: String? = null,
    val isEnvironmentSafe: Boolean = true,
    val securityTestResult: String? = null,
    val securityTestSuccess: Boolean = true
)

package com.gargpadmakar.mtproto.crypto.presentation.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.presentation.components.CryptoInfoCard
import com.gargpadmakar.mtproto.crypto.presentation.components.SectionHeader
import com.gargpadmakar.mtproto.crypto.presentation.components.StatusBanner
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.EncryptionViewModel

@Composable
fun EncryptionScreen(
    viewModel: EncryptionViewModel,
    modifier: Modifier = Modifier
) {
    val uiState by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        SectionHeader(
            title = "MTProto 2.0 Encryption",
            subtitle = "AES-256-IGE with 12..1024 bytes random padding"
        )

        // Session Key Card
        CryptoInfoCard(
            label = "Active Auth Key (2048-bit)",
            value = uiState.authKeyHex,
            onCopy = {}
        )

        CryptoInfoCard(
            label = "auth_key_id (Lower 64 bits of SHA-1)",
            value = uiState.authKeyIdHex,
            onCopy = {}
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedButton(
                onClick = { viewModel.generateNewKey() }
            ) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "New Session",
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.size(6.dp))
                Text("New DH Session")
            }

            // Direction chips
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(
                    selected = uiState.direction == EncryptionDirection.CLIENT_TO_SERVER,
                    onClick = { viewModel.onDirectionChanged(EncryptionDirection.CLIENT_TO_SERVER) },
                    label = { Text("Client->Server") }
                )
                FilterChip(
                    selected = uiState.direction == EncryptionDirection.SERVER_TO_CLIENT,
                    onClick = { viewModel.onDirectionChanged(EncryptionDirection.SERVER_TO_CLIENT) },
                    label = { Text("Server->Client") }
                )
            }
        }

        // Input Text
        OutlinedTextField(
            value = uiState.inputText,
            onValueChange = { viewModel.onInputTextChanged(it) },
            label = { Text("Plaintext Message") },
            placeholder = { Text("Enter text to encrypt using MTProto 2.0...") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
            maxLines = 6
        )

        Button(
            onClick = { viewModel.encryptText() },
            modifier = Modifier.fillMaxWidth(),
            enabled = !uiState.isLoading && uiState.inputText.isNotBlank()
        ) {
            if (uiState.isLoading) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(modifier = Modifier.size(8.dp))
                Text("Encrypting...")
            } else {
                Icon(imageVector = Icons.Default.Lock, contentDescription = "Encrypt")
                Spacer(modifier = Modifier.size(8.dp))
                Text("Encrypt Message")
            }
        }

        StatusBanner(
            status = uiState.statusMessage,
            error = uiState.errorMessage
        )

        // Output Display
        uiState.encryptedWireBase64?.let { base64 ->
            SectionHeader(
                title = "Encrypted Output",
                subtitle = "Wire format: auth_key_id (8) + msg_key (16) + encrypted_data"
            )

            uiState.msgKeyHex?.let {
                CryptoInfoCard(
                    label = "msg_key (Middle 128 bits SHA-256)",
                    value = it,
                    onCopy = {}
                )
            }

            CryptoInfoCard(
                label = "Wire Base64 Ciphertext",
                value = base64,
                onCopy = {}
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}


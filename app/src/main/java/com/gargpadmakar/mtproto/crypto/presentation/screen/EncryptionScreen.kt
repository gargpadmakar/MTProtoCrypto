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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
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
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .verticalScroll(scrollState),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        SectionHeader(
            title = "MTProto 2.0 Encryption",
            subtitle = "AES-256-IGE with 12..1024 bytes random padding"
        )

        // Session Card Grouping
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Key,
                            contentDescription = "Session",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.size(6.dp))
                        Text(
                            text = "Active Session Key",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }

                    OutlinedButton(
                        onClick = { viewModel.generateNewKey() },
                        shape = RoundedCornerShape(20.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "New Session",
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.size(4.dp))
                        Text("New DH", style = MaterialTheme.typography.labelMedium)
                    }
                }

                CryptoInfoCard(
                    label = "auth_key (2048-bit)",
                    value = uiState.authKeyHex,
                    onCopy = {}
                )

                CryptoInfoCard(
                    label = "auth_key_id (Lower 64 bits SHA-1)",
                    value = uiState.authKeyIdHex,
                    onCopy = {}
                )
            }
        }

        // Direction Selector (50% - 50% Full Width Row)
        Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = "Direction (KDF Offset)",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.secondary,
                fontWeight = FontWeight.SemiBold
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = uiState.direction == EncryptionDirection.CLIENT_TO_SERVER,
                    onClick = { viewModel.onDirectionChanged(EncryptionDirection.CLIENT_TO_SERVER) },
                    label = {
                        Text(
                            text = "Client -> Server",
                            modifier = Modifier.fillMaxWidth(),
                            textAlign = TextAlign.Center,
                            style = MaterialTheme.typography.labelLarge
                        )
                    },
                    modifier = Modifier.weight(1f)
                )
                FilterChip(
                    selected = uiState.direction == EncryptionDirection.SERVER_TO_CLIENT,
                    onClick = { viewModel.onDirectionChanged(EncryptionDirection.SERVER_TO_CLIENT) },
                    label = {
                        Text(
                            text = "Server -> Client",
                            modifier = Modifier.fillMaxWidth(),
                            textAlign = TextAlign.Center,
                            style = MaterialTheme.typography.labelLarge
                        )
                    },
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Input Plaintext
        OutlinedTextField(
            value = uiState.inputText,
            onValueChange = { viewModel.onInputTextChanged(it) },
            label = { Text("Plaintext Message") },
            placeholder = { Text("Enter text to encrypt using MTProto 2.0...") },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            minLines = 3,
            maxLines = 6
        )

        Button(
            onClick = { viewModel.encryptText() },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
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

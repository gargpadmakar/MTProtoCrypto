package com.gargpadmakar.mtproto.crypto.presentation.screen

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.presentation.components.CryptoInfoCard
import com.gargpadmakar.mtproto.crypto.presentation.components.SectionHeader
import com.gargpadmakar.mtproto.crypto.presentation.components.StatusBanner
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.DecryptionViewModel

@Composable
fun DecryptionScreen(
    viewModel: DecryptionViewModel,
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
            title = "MTProto 2.0 Decryption",
            subtitle = "Constant-time msg_key integrity verification before plaintext release"
        )

        // Session Key Card
        CryptoInfoCard(
            label = "Active Auth Key (2048-bit)",
            value = uiState.authKeyHex.ifEmpty { "Synchronized with active session" }
        )

        // Direction Selector (50% - 50% Full Width Row)
        Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = "Direction (KDF Offset)",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.secondary
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

        // Ciphertext Input
        OutlinedTextField(
            value = uiState.inputCiphertextBase64,
            onValueChange = { viewModel.onCiphertextChanged(it) },
            label = { Text("Encrypted Wire Ciphertext (Base64)") },
            placeholder = { Text("Paste Base64 MTProto 2.0 ciphertext here...") },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            minLines = 3,
            maxLines = 6
        )

        Button(
            onClick = { viewModel.decryptText() },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
            enabled = !uiState.isLoading && uiState.inputCiphertextBase64.isNotBlank()
        ) {
            if (uiState.isLoading) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                Spacer(modifier = Modifier.size(8.dp))
                Text("Verifying & Decrypting...")
            } else {
                Icon(imageVector = Icons.Default.LockOpen, contentDescription = "Decrypt")
                Spacer(modifier = Modifier.size(8.dp))
                Text("Verify & Decrypt")
            }
        }

        StatusBanner(
            status = uiState.statusMessage,
            error = uiState.errorMessage
        )

        // Decrypted Output
        uiState.decryptedText?.let { plaintext ->
            if (uiState.isVerified) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f))
                        .padding(14.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "Verified",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.size(10.dp))
                        Text(
                            text = "msg_key integrity verified in constant-time. No tampering detected.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    }
                }
            }

            SectionHeader(
                title = "Verified Plaintext",
                subtitle = "Padding stripped (${uiState.paddingLength} bytes padding removed)"
            )

            CryptoInfoCard(
                label = "Decrypted Message",
                value = plaintext,
                onCopy = {}
            )

            uiState.authKeyIdHex?.let {
                CryptoInfoCard(
                    label = "Verified auth_key_id",
                    value = it,
                    onCopy = {}
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

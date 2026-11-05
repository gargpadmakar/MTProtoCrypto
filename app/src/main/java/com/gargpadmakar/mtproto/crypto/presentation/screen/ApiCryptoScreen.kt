package com.gargpadmakar.mtproto.crypto.presentation.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.gargpadmakar.mtproto.crypto.presentation.components.CryptoInfoCard
import com.gargpadmakar.mtproto.crypto.presentation.components.SectionHeader
import com.gargpadmakar.mtproto.crypto.presentation.components.StatusBanner
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.ApiCryptoViewModel

@Composable
fun ApiCryptoScreen(
    viewModel: ApiCryptoViewModel,
    modifier: Modifier = Modifier
) {
    val uiState by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()
    val clipboardManager = LocalClipboardManager.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Title & Description
        Column {
            Text(
                text = "API Payload Encryption",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                text = "End-to-End MTProto 2.0 REST Encryption & Anti-Reverse Engineering",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // Status Banner
        uiState.statusMessage?.let { message ->
            StatusBanner(
                status = if (!uiState.isError) message else null,
                error = if (uiState.isError) message else null
            )
        }

        // Ephemeral Session Key Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        modifier = Modifier.weight(1f, fill = false),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Key,
                            contentDescription = "Session Key",
                            tint = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                        Text(
                            text = "Ephemeral Session",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                    }

                    FilledTonalButton(
                        onClick = { viewModel.regenerateSessionKey() },
                        shape = RoundedCornerShape(8.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "New Key",
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(text = "New Key", style = MaterialTheme.typography.labelMedium)
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Auth Key ID: ${uiState.authKeyIdHex}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = "Zero static keys in APK: Key is generated dynamically in memory via 2048-bit Diffie-Hellman handshake.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.8f)
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = "Integrity",
                        modifier = Modifier.size(16.dp),
                        tint = if (uiState.isEnvironmentSafe) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.size(6.dp))
                    Text(
                        text = if (uiState.isEnvironmentSafe) "Environment Safe: No Root / Frida / Debugger detected" else "Warning: Tampered Environment Detected",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        // Section: Outgoing API Request
        SectionHeader(title = "1. API Request Payload (JSON)")

        OutlinedTextField(
            value = uiState.requestJson,
            onValueChange = { viewModel.onJsonChanged(it) },
            label = { Text("Request Body (JSON)") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 4,
            maxLines = 8,
            shape = RoundedCornerShape(12.dp),
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)
        )

        Button(
            onClick = { viewModel.encryptRequest() },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            enabled = !uiState.isLoading
        ) {
            if (uiState.isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp
                )
                Spacer(modifier = Modifier.size(8.dp))
            }
            Icon(imageVector = Icons.Default.Lock, contentDescription = "Encrypt")
            Spacer(modifier = Modifier.size(8.dp))
            Text(text = "Encrypt API Request (Client -> Server)")
        }

        // Section: Encrypted Wire Packet
        if (uiState.encryptedJsonWire.isNotEmpty()) {
            SectionHeader(title = "2. Encrypted Wire HTTP Body")

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = uiState.encryptedJsonWire,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedButton(
                        onClick = {
                            clipboardManager.setText(AnnotatedString(uiState.encryptedJsonWire))
                        },
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(text = "Copy Wire JSON")
                    }
                }
            }

            // Section: Server Simulation
            SectionHeader(title = "3. Server Roundtrip & Response Decryption")

            Button(
                onClick = { viewModel.simulateServerRoundtrip() },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                enabled = !uiState.isLoading
            ) {
                Icon(imageVector = Icons.Default.CloudDone, contentDescription = "Roundtrip")
                Spacer(modifier = Modifier.size(8.dp))
                Text(text = "Simulate Node.js Roundtrip & Decrypt Response")
            }
        }

        // Section: Decrypted Response
        if (uiState.decryptedResponseJson.isNotEmpty()) {
            CryptoInfoCard(
                label = "Authenticated Server Response (Plaintext JSON)",
                value = uiState.decryptedResponseJson,
                onCopy = {
                    clipboardManager.setText(AnnotatedString(uiState.decryptedResponseJson))
                }
            )
        }

        // Section: Security & Reverse-Engineering Live Tests
        SectionHeader(title = "4. Anti-Reverse Engineering Tests")

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = { viewModel.testTamperDetection() },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
            ) {
                Text(text = "Tamper Test", style = MaterialTheme.typography.labelMedium)
            }

            OutlinedButton(
                onClick = { viewModel.testReplayAttackDetection() },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
            ) {
                Text(text = "Replay Test", style = MaterialTheme.typography.labelMedium)
            }
        }

        uiState.securityTestResult?.let { result ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (uiState.securityTestSuccess)
                        MaterialTheme.colorScheme.primaryContainer
                    else
                        MaterialTheme.colorScheme.errorContainer
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = if (uiState.securityTestSuccess) "Security Test: Passed" else "Security Test: Failed",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (uiState.securityTestSuccess)
                            MaterialTheme.colorScheme.onPrimaryContainer
                        else
                            MaterialTheme.colorScheme.onErrorContainer
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = result,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = if (uiState.securityTestSuccess)
                            MaterialTheme.colorScheme.onPrimaryContainer
                        else
                            MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }
    }
}

package com.gargpadmakar.mtproto.crypto.presentation.screen

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.gargpadmakar.mtproto.crypto.presentation.components.CryptoInfoCard
import com.gargpadmakar.mtproto.crypto.presentation.components.SectionHeader
import com.gargpadmakar.mtproto.crypto.presentation.components.StatusBanner
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.MediaEncryptionViewModel

@Composable
fun MediaEncryptionScreen(
    viewModel: MediaEncryptionViewModel,
    modifier: Modifier = Modifier
) {
    val uiState by viewModel.uiState.collectAsState()
    val scrollState = rememberScrollState()

    // SAF File Picker for all supported MIME types
    val pickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { viewModel.onMediaSelected(it) }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .verticalScroll(scrollState),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        SectionHeader(
            title = "Secret Chat Media Encryption",
            subtitle = "AES-256-IGE streaming encryption for large media (Images, Videos, Audio, Docs)"
        )

        // File Selector Button
        OutlinedButton(
            onClick = { pickerLauncher.launch(arrayOf("*/*")) },
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Icon(imageVector = Icons.Default.FileOpen, contentDescription = "Pick file")
            Spacer(modifier = Modifier.size(8.dp))
            Text(if (uiState.selectedFileName != null) "Change Media File" else "Select Media File (SAF)")
        }

        uiState.selectedFileName?.let { name ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
                shape = RoundedCornerShape(14.dp)
            ) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "Selected File",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.secondary
                    )
                    Text(
                        text = name,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    val sizeFormatted = formatBytes(uiState.selectedFileSize)
                    Text(
                        text = "$sizeFormatted • ${uiState.selectedMimeType}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // Progress Bar
            if (uiState.isProcessing) {
                Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    LinearProgressIndicator(
                        progress = { uiState.progressFraction },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp)
                            .clip(RoundedCornerShape(4.dp))
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "${formatBytes(uiState.bytesProcessed)} / ${formatBytes(uiState.totalBytes)}",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            text = "${(uiState.progressFraction * 100).toInt()}%",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }

                Button(
                    onClick = { viewModel.cancelOperation() },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(imageVector = Icons.Default.Cancel, contentDescription = "Cancel")
                    Spacer(modifier = Modifier.size(8.dp))
                    Text("Cancel Streaming Operation")
                }
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = { viewModel.startMediaEncryption() },
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(imageVector = Icons.Default.Lock, contentDescription = "Encrypt Media")
                        Spacer(modifier = Modifier.size(6.dp))
                        Text("Encrypt Stream")
                    }

                    if (uiState.encryptedFilePath != null) {
                        Button(
                            onClick = { viewModel.startMediaDecryption() },
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Icon(imageVector = Icons.Default.LockOpen, contentDescription = "Decrypt Media")
                            Spacer(modifier = Modifier.size(6.dp))
                            Text("Decrypt Stream")
                        }
                    }
                }
            }
        }

        StatusBanner(
            status = uiState.statusMessage,
            error = uiState.errorMessage
        )

        // Metadata display
        uiState.metadata?.let { meta ->
            SectionHeader(
                title = "Secret Chat Media Metadata",
                subtitle = "Random 256-bit media key & IV generated via SecureRandom"
            )

            CryptoInfoCard(
                label = "Media Key (Base64)",
                value = meta.keyBase64(),
                onCopy = {}
            )

            CryptoInfoCard(
                label = "Media IV (Base64)",
                value = meta.ivBase64(),
                onCopy = {}
            )

            CryptoInfoCard(
                label = "Key Fingerprint (64-bit)",
                value = meta.keyFingerprint.toString(),
                onCopy = {}
            )
        }

        // Verification banner
        if (uiState.isDecryptedVerified) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.8f))
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
                        text = "Lossless Round-Trip Verified: Decrypted file perfectly matches original file size and byte structure.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
    val pre = "KMGTPE"[exp - 1]
    return String.format("%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
}

package com.gargpadmakar.mtproto.crypto.presentation.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.gargpadmakar.mtproto.crypto.presentation.components.CryptoInfoCard
import com.gargpadmakar.mtproto.crypto.presentation.components.SectionHeader
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.SecurityInfoViewModel

@Composable
fun SecurityInfoScreen(
    viewModel: SecurityInfoViewModel,
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
            title = "Security & Cryptographic Specifications",
            subtitle = "MTProto 2.0 and Secret Chat Media Cryptographic Architecture"
        )

        CryptoInfoCard(
            label = "Cipher Mode",
            value = uiState.algorithmName
        )

        CryptoInfoCard(
            label = "Key & IV Dimensions",
            value = "Key: ${uiState.keySizeBits} bits (32 bytes) | IV: ${uiState.ivSizeBits} bits (32 bytes = y_0 || x_0)"
        )

        CryptoInfoCard(
            label = "Key Derivation Function (KDF)",
            value = uiState.kdfDescription
        )

        CryptoInfoCard(
            label = "Diffie-Hellman Key Exchange",
            value = uiState.dhGroup
        )

        CryptoInfoCard(
            label = "Message Padding (MTProto 2.0)",
            value = uiState.paddingRule
        )

        CryptoInfoCard(
            label = "Secret Chat Media Mode",
            value = uiState.secretChatMediaMode
        )

        Card(
            modifier = Modifier.padding(vertical = 4.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f))
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = "Key Security Architecture Highlights",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "• Constant-Time Verification: msg_key verification uses MessageDigest.isEqual() to prevent timing attacks before releasing any plaintext.\n\n" +
                            "• Zeroization Best-Effort: Sensitive buffers and intermediate keys are cleared via SecureBytes.wipe() and try/finally blocks.\n\n" +
                            "• Strict Separation: MTProto transport encryption (auth_key + KDF + random padding) is distinctly decoupled from Telegram Secret Chat media encryption (random media key + IV).\n\n" +
                            "• Thread Safety: Independent cipher engine instances and defensive copying ensure concurrent thread safety without shared mutable cryptographic state.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}


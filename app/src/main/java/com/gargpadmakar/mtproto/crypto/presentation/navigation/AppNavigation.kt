package com.gargpadmakar.mtproto.crypto.presentation.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.PermMedia
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.gargpadmakar.mtproto.crypto.presentation.screen.DecryptionScreen
import com.gargpadmakar.mtproto.crypto.presentation.screen.EncryptionScreen
import com.gargpadmakar.mtproto.crypto.presentation.screen.MediaEncryptionScreen
import com.gargpadmakar.mtproto.crypto.presentation.screen.SecurityInfoScreen
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.DecryptionViewModel
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.EncryptionViewModel
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.MediaEncryptionViewModel
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.SecurityInfoViewModel
import org.koin.androidx.compose.koinViewModel

enum class AppDestination(val label: String, val icon: ImageVector) {
    ENCRYPTION("Encrypt", Icons.Default.Lock),
    DECRYPTION("Decrypt", Icons.Default.LockOpen),
    MEDIA("Media", Icons.Default.PermMedia),
    SECURITY("Security", Icons.Default.Security)
}

@Composable
fun AppNavigation(
    encryptionViewModel: EncryptionViewModel = koinViewModel(),
    decryptionViewModel: DecryptionViewModel = koinViewModel(),
    mediaViewModel: MediaEncryptionViewModel = koinViewModel(),
    securityViewModel: SecurityInfoViewModel = koinViewModel()
) {
    var currentDestination by remember { mutableStateOf(AppDestination.ENCRYPTION) }

    // Sync auth key from EncryptionViewModel to DecryptionViewModel
    val encState by encryptionViewModel.uiState.collectAsState()
    LaunchedEffect(encState.authKeyHex) {
        decryptionViewModel.setAuthKey(encryptionViewModel.getActiveAuthKeyCopy())
    }

    // Auto-populate ciphertext when navigating to Decrypt tab if available
    LaunchedEffect(currentDestination) {
        if (currentDestination == AppDestination.DECRYPTION && encState.encryptedWireBase64 != null) {
            if (decryptionViewModel.uiState.value.inputCiphertextBase64.isBlank()) {
                decryptionViewModel.onCiphertextChanged(encState.encryptedWireBase64!!)
            }
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                AppDestination.values().forEach { destination ->
                    NavigationBarItem(
                        selected = currentDestination == destination,
                        onClick = { currentDestination = destination },
                        icon = { Icon(imageVector = destination.icon, contentDescription = destination.label) },
                        label = { Text(destination.label) }
                    )
                }
            }
        }
    ) { innerPadding ->
        when (currentDestination) {
            AppDestination.ENCRYPTION -> EncryptionScreen(
                viewModel = encryptionViewModel,
                modifier = Modifier.padding(innerPadding)
            )
            AppDestination.DECRYPTION -> DecryptionScreen(
                viewModel = decryptionViewModel,
                modifier = Modifier.padding(innerPadding)
            )
            AppDestination.MEDIA -> MediaEncryptionScreen(
                viewModel = mediaViewModel,
                modifier = Modifier.padding(innerPadding)
            )
            AppDestination.SECURITY -> SecurityInfoScreen(
                viewModel = securityViewModel,
                modifier = Modifier.padding(innerPadding)
            )
        }
    }
}


package com.gargpadmakar.mtproto.crypto

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.gargpadmakar.mtproto.crypto.presentation.navigation.AppNavigation
import com.gargpadmakar.mtproto.crypto.ui.theme.MTProtoCryptoTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MTProtoCryptoTheme {
                AppNavigation()
            }
        }
    }
}
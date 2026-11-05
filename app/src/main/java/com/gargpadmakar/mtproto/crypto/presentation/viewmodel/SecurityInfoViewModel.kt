package com.gargpadmakar.mtproto.crypto.presentation.viewmodel

import androidx.lifecycle.ViewModel
import com.gargpadmakar.mtproto.crypto.presentation.state.SecurityInfoUiState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class SecurityInfoViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(SecurityInfoUiState())
    val uiState: StateFlow<SecurityInfoUiState> = _uiState.asStateFlow()
}


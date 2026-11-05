package com.gargpadmakar.mtproto.crypto.di

import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.ApiCryptoViewModel
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.DecryptionViewModel
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.EncryptionViewModel
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.MediaEncryptionViewModel
import com.gargpadmakar.mtproto.crypto.presentation.viewmodel.SecurityInfoViewModel
import org.koin.android.ext.koin.androidApplication
import org.koin.core.module.Module
import org.koin.core.module.dsl.viewModel
import org.koin.dsl.module

val presentationModule: Module = module {
    viewModel { EncryptionViewModel(get(), get(), get(), get()) }
    viewModel { DecryptionViewModel(get(), get()) }
    viewModel { MediaEncryptionViewModel(androidApplication(), get(), get()) }
    viewModel { SecurityInfoViewModel() }
    viewModel { ApiCryptoViewModel(get(), get(), get()) }
}

val appModules: List<Module> = listOf(
    presentationModule
)

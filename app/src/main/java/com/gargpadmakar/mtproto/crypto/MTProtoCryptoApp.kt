package com.gargpadmakar.mtproto.crypto

import android.app.Application
import com.gargpadmakar.mtproto.crypto.di.appModules
import com.gargpadmakar.mtproto.crypto.di.mtProtoSdkModules
import org.koin.android.ext.koin.androidContext
import org.koin.android.ext.koin.androidLogger
import org.koin.core.context.startKoin

class MTProtoCryptoApp : Application() {
    override fun onCreate() {
        super.onCreate()
        startKoin {
            androidLogger()
            androidContext(this@MTProtoCryptoApp)
            modules(mtProtoSdkModules + appModules)
        }
    }
}


package com.gargpadmakar.mtproto.crypto.di

import com.gargpadmakar.mtproto.crypto.data.crypto.AesIgeCipher
import com.gargpadmakar.mtproto.crypto.data.crypto.ApiCryptoEngine
import com.gargpadmakar.mtproto.crypto.data.crypto.DhHandshakeEngine
import com.gargpadmakar.mtproto.crypto.data.crypto.MTProtoKdf
import com.gargpadmakar.mtproto.crypto.data.crypto.MediaCipher
import com.gargpadmakar.mtproto.crypto.data.crypto.MessageCipher
import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoApiRepositoryImpl
import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoCipherRepositoryImpl
import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoHandshakeRepositoryImpl
import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoKdfRepositoryImpl
import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoMediaRepositoryImpl
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoApiRepository
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoCipherRepository
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoHandshakeRepository
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoKdfRepository
import com.gargpadmakar.mtproto.crypto.domain.repository.MTProtoMediaRepository
import com.gargpadmakar.mtproto.crypto.domain.usecase.CalculateMessageKeyUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.DecryptApiResponseUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.DecryptMediaUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.DecryptTextUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.DeriveAesKeyUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.EncryptApiRequestUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.EncryptMediaUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.EncryptTextUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.GenerateAuthorizationKeyUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.ValidateDhParametersUseCase
import com.gargpadmakar.mtproto.crypto.security.KeyManager
import org.koin.core.module.Module
import org.koin.dsl.module
import java.security.SecureRandom

/**
 * Koin module providing cryptographic engines and secure utilities.
 */
val cryptoModule: Module = module {
    single { SecureRandom() }
    single { AesIgeCipher() }
    single { MTProtoKdf() }
    single { DhHandshakeEngine(get()) }
    single { MessageCipher(get(), get(), get()) }
    single { MediaCipher(get(), get()) }
    single { ApiCryptoEngine(get(), get(), get()) }
    single { KeyManager() }
}

/**
 * Koin module providing Clean Architecture repository implementations.
 */
val repositoryModule: Module = module {
    single<MTProtoCipherRepository> { MTProtoCipherRepositoryImpl(get(), get()) }
    single<MTProtoKdfRepository> { MTProtoKdfRepositoryImpl(get()) }
    single<MTProtoHandshakeRepository> { MTProtoHandshakeRepositoryImpl(get()) }
    single<MTProtoMediaRepository> { MTProtoMediaRepositoryImpl(get()) }
    single<MTProtoApiRepository> { MTProtoApiRepositoryImpl(get()) }
}

/**
 * Koin module providing domain UseCases.
 */
val useCaseModule: Module = module {
    factory { EncryptTextUseCase(get()) }
    factory { DecryptTextUseCase(get()) }
    factory { EncryptMediaUseCase(get()) }
    factory { DecryptMediaUseCase(get()) }
    factory { DeriveAesKeyUseCase(get()) }
    factory { CalculateMessageKeyUseCase(get()) }
    factory { GenerateAuthorizationKeyUseCase(get()) }
    factory { ValidateDhParametersUseCase(get()) }
    factory { EncryptApiRequestUseCase(get()) }
    factory { DecryptApiResponseUseCase(get()) }
}

/**
 * Convenience list containing all SDK modules for host applications.
 */
val mtProtoSdkModules: List<Module> = listOf(
    cryptoModule,
    repositoryModule,
    useCaseModule
)

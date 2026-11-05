package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoCipherRepositoryImpl
import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoHandshakeRepositoryImpl
import com.gargpadmakar.mtproto.crypto.data.repository.MTProtoKdfRepositoryImpl
import com.gargpadmakar.mtproto.crypto.domain.model.EncryptionDirection
import com.gargpadmakar.mtproto.crypto.domain.usecase.CalculateMessageKeyUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.DecryptTextUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.DeriveAesKeyUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.EncryptTextUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.GenerateAuthorizationKeyUseCase
import com.gargpadmakar.mtproto.crypto.domain.usecase.ValidateDhParametersUseCase
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class UseCaseTest {

    private val cipherRepo = MTProtoCipherRepositoryImpl()
    private val kdfRepo = MTProtoKdfRepositoryImpl()
    private val handshakeRepo = MTProtoHandshakeRepositoryImpl()

    private val encryptTextUseCase = EncryptTextUseCase(cipherRepo)
    private val decryptTextUseCase = DecryptTextUseCase(cipherRepo)
    private val deriveAesKeyUseCase = DeriveAesKeyUseCase(kdfRepo)
    private val calculateMessageKeyUseCase = CalculateMessageKeyUseCase(kdfRepo)
    private val generateAuthKeyUseCase = GenerateAuthorizationKeyUseCase(handshakeRepo)
    private val validateDhParamsUseCase = ValidateDhParametersUseCase(handshakeRepo)

    private val random = Random(777)

    @Test
    fun testEncryptAndDecryptTextUseCases() = runBlocking {
        val authKey = ByteArray(256).also { random.nextBytes(it) }
        val testText = "Clean Architecture UseCase integration test"

        val encResult = encryptTextUseCase(testText, authKey, EncryptionDirection.CLIENT_TO_SERVER)
        assertTrue(encResult.isSuccess)
        val encryptedMessage = encResult.getOrThrow()

        val decResult = decryptTextUseCase(encryptedMessage, authKey, EncryptionDirection.CLIENT_TO_SERVER)
        assertTrue(decResult.isSuccess)
        val decryptedMessage = decResult.getOrThrow()

        assertEquals(testText, decryptedMessage.text())
    }

    @Test
    fun testDeriveAesKeyUseCase() {
        val authKey = ByteArray(256).also { random.nextBytes(it) }
        val msgKey = ByteArray(16).also { random.nextBytes(it) }

        val result = deriveAesKeyUseCase(authKey, msgKey)
        assertTrue(result.isSuccess)
        val keys = result.getOrThrow()
        assertEquals(32, keys.aesKey.size)
        assertEquals(32, keys.aesIv.size)
    }

    @Test
    fun testGenerateAuthKeyAndValidateParamsUseCases() {
        val params = generateAuthKeyUseCase.getDefaultParameters()
        val validateResult = validateDhParamsUseCase(params)
        assertTrue(validateResult.isSuccess)

        val alice = generateAuthKeyUseCase.generateKeyPair(params)
        val bob = generateAuthKeyUseCase.generateKeyPair(params)

        val aliceAuthResult = generateAuthKeyUseCase(bob.publicValue, alice.privateExponent, params)
        val bobAuthResult = generateAuthKeyUseCase(alice.publicValue, bob.privateExponent, params)

        assertTrue(aliceAuthResult.isSuccess)
        assertTrue(bobAuthResult.isSuccess)

        val aliceKey = aliceAuthResult.getOrThrow()
        val bobKey = bobAuthResult.getOrThrow()

        assertTrue(aliceKey.authKey.contentEquals(bobKey.authKey))
        assertTrue(aliceKey.authKeyId.contentEquals(bobKey.authKeyId))
    }
}


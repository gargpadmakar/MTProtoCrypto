package com.gargpadmakar.mtproto.crypto

import com.gargpadmakar.mtproto.crypto.data.crypto.DhHandshakeEngine
import com.gargpadmakar.mtproto.crypto.domain.exception.DHValidationException
import com.gargpadmakar.mtproto.crypto.domain.model.DhParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class DhHandshakeTest {

    private val handshakeEngine = DhHandshakeEngine()

    @Test
    fun testTelegramDefaultDhParametersValidation() {
        val params = DhHandshakeEngine.DEFAULT_DH_PARAMETERS
        assertEquals(2, params.generatorG)
        assertEquals(2048, params.primeP.bitLength())

        // Must validate without throwing
        handshakeEngine.validateDhParameters(params)
    }

    @Test
    fun testDiffieHellmanKeyAgreement() {
        val params = DhHandshakeEngine.DEFAULT_DH_PARAMETERS

        // Alice generates keypair
        val aliceKeyPair = handshakeEngine.generateKeyPair(params)
        assertTrue(aliceKeyPair.publicValue > BigInteger.ONE)

        // Bob generates keypair
        val bobKeyPair = handshakeEngine.generateKeyPair(params)
        assertTrue(bobKeyPair.publicValue > BigInteger.ONE)

        // Alice computes shared auth_key from Bob's public value
        val aliceResult = handshakeEngine.computeAuthKey(
            peerPublicValue = bobKeyPair.publicValue,
            privateExponent = aliceKeyPair.privateExponent,
            params = params
        )

        // Bob computes shared auth_key from Alice's public value
        val bobResult = handshakeEngine.computeAuthKey(
            peerPublicValue = aliceKeyPair.publicValue,
            privateExponent = bobKeyPair.privateExponent,
            params = params
        )

        assertEquals(256, aliceResult.authKey.size)
        assertEquals(256, bobResult.authKey.size)
        assertEquals(8, aliceResult.authKeyId.size)
        assertEquals(8, bobResult.authKeyId.size)

        // Mathematical key agreement verification
        assertArrayEquals(aliceResult.authKey, bobResult.authKey)
        assertArrayEquals(aliceResult.authKeyId, bobResult.authKeyId)
    }

    @Test(expected = DHValidationException::class)
    fun testInvalidGeneratorThrows() {
        val invalidParams = DhParameters(DhHandshakeEngine.TELEGRAM_DH_PRIME, 8) // g = 8 (outside 2..7)
        handshakeEngine.validateDhParameters(invalidParams)
    }

    @Test(expected = DHValidationException::class)
    fun testOutOfBoundsPublicValueThrows() {
        val params = DhHandshakeEngine.DEFAULT_DH_PARAMETERS
        // g_a = 1 is invalid (must be > 1)
        handshakeEngine.validatePublicValue(BigInteger.ONE, params.primeP)
    }
}


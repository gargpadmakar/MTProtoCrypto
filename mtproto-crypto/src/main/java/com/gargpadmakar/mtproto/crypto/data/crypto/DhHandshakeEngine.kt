package com.gargpadmakar.mtproto.crypto.data.crypto

import com.gargpadmakar.mtproto.crypto.domain.exception.DHValidationException
import com.gargpadmakar.mtproto.crypto.domain.model.AuthKeyResult
import com.gargpadmakar.mtproto.crypto.domain.model.DhKeyPair
import com.gargpadmakar.mtproto.crypto.domain.model.DhParameters
import com.gargpadmakar.mtproto.crypto.security.SecureBytes
import java.math.BigInteger
import java.security.SecureRandom

/**
 * MTProto Diffie-Hellman (DH) Handshake engine.
 *
 * Implements 2048-bit Diffie-Hellman key agreement for authorization key creation
 * following the MTProto specification.
 *
 * NOTE: Standard Java [BigInteger.modPow] on the JVM is NOT constant-time.
 * Avoid timing side channels by utilizing high-entropy exponents and secure random generation.
 */
class DhHandshakeEngine(
    private val secureRandom: SecureRandom = SecureRandom()
) {

    companion object {
        const val AUTH_KEY_BYTE_LENGTH = 256
        const val DH_PRIME_BIT_LENGTH = 2048

        /**
         * Standard Telegram 2048-bit MODP safe prime (RFC 3526 Group 14).
         */
        val TELEGRAM_DH_PRIME_HEX: String = (
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
        ).trim()

        val TELEGRAM_DH_PRIME = BigInteger(TELEGRAM_DH_PRIME_HEX, 16)
        const val TELEGRAM_DH_GENERATOR = 2

        val DEFAULT_DH_PARAMETERS = DhParameters(TELEGRAM_DH_PRIME, TELEGRAM_DH_GENERATOR)
    }

    private val kdf = MTProtoKdf()

    /**
     * Validates DH parameters received from the server.
     *
     * Rules from MTProto specification:
     * 1. g must be in {2, 3, 4, 5, 6, 7}.
     * 2. p must be 2048-bit integer.
     * 3. p must be a safe prime: p is prime and (p - 1) / 2 is prime.
     */
    fun validateDhParameters(params: DhParameters, checkSafePrime: Boolean = true) {
        val g = params.generatorG
        if (g !in 2..7) {
            throw DHValidationException("DH generator g must be in range [2, 7], got $g")
        }

        val p = params.primeP
        if (p.bitLength() != DH_PRIME_BIT_LENGTH) {
            throw DHValidationException("DH prime p must be exactly 2048 bits, got ${p.bitLength()} bits")
        }

        // Fast check against standardized Telegram prime
        if (p == TELEGRAM_DH_PRIME) {
            return
        }

        if (!p.isProbablePrime(64)) {
            throw DHValidationException("DH parameter p is not prime")
        }

        if (checkSafePrime) {
            val q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
            if (!q.isProbablePrime(64)) {
                throw DHValidationException("DH parameter p is not a safe prime ((p-1)/2 is composite)")
            }
        }
    }

    /**
     * Validates a public DH value (g^a or g^b).
     *
     * Rules from MTProto:
     * 1 < g_a < p - 1
     * 2^(2048 - 64) <= g_a <= p - 2^(2048 - 64) (mitigates small subgroup attacks)
     */
    fun validatePublicValue(publicValue: BigInteger, primeP: BigInteger) {
        if (publicValue <= BigInteger.ONE || publicValue >= primeP.subtract(BigInteger.ONE)) {
            throw DHValidationException("Public DH value out of valid bounds (1 < g_a < p - 1)")
        }

        // 2^(2048 - 64) = 2^1984
        val minBound = BigInteger.ONE.shiftLeft(DH_PRIME_BIT_LENGTH - 64)
        val maxBound = primeP.subtract(minBound)

        if (publicValue < minBound || publicValue > maxBound) {
            throw DHValidationException("Public DH value outside safe subgroup range [2^1984, p - 2^1984]")
        }
    }

    /**
     * Generates a DH keypair (private exponent a and public value g^a mod p).
     */
    fun generateKeyPair(params: DhParameters): DhKeyPair {
        validateDhParameters(params, checkSafePrime = false)

        // Generate 2048-bit random private exponent with top bits set
        val privateBytes = ByteArray(AUTH_KEY_BYTE_LENGTH)
        secureRandom.nextBytes(privateBytes)
        // Ensure positive BigInteger
        var a = BigInteger(1, privateBytes)
        SecureBytes.wipe(privateBytes)

        val minExponent = BigInteger.ONE.shiftLeft(DH_PRIME_BIT_LENGTH - 64)
        if (a < minExponent) {
            a = a.add(minExponent)
        }

        val g = BigInteger.valueOf(params.generatorG.toLong())
        val publicValue = g.modPow(a, params.primeP)

        return DhKeyPair(privateExponent = a, publicValue = publicValue)
    }

    /**
     * Computes the 256-byte authorization key auth_key = (peerPublicValue)^privateExponent mod p.
     * Also calculates auth_key_id.
     */
    fun computeAuthKey(
        peerPublicValue: BigInteger,
        privateExponent: BigInteger,
        params: DhParameters
    ): AuthKeyResult {
        validatePublicValue(peerPublicValue, params.primeP)

        // (peerPublicValue)^privateExponent mod p
        val sharedBigInt = peerPublicValue.modPow(privateExponent, params.primeP)
        val rawBytes = sharedBigInt.toByteArray()

        // Normalize to exactly 256 bytes (Big Endian, removing potential extra sign byte or prepending zeros)
        val authKey = ByteArray(AUTH_KEY_BYTE_LENGTH)
        if (rawBytes.size == AUTH_KEY_BYTE_LENGTH) {
            System.arraycopy(rawBytes, 0, authKey, 0, AUTH_KEY_BYTE_LENGTH)
        } else if (rawBytes.size > AUTH_KEY_BYTE_LENGTH) {
            // Strip leading zero byte from signed BigInteger representation
            val offset = rawBytes.size - AUTH_KEY_BYTE_LENGTH
            System.arraycopy(rawBytes, offset, authKey, 0, AUTH_KEY_BYTE_LENGTH)
        } else {
            // Prepend leading zeros
            val offset = AUTH_KEY_BYTE_LENGTH - rawBytes.size
            System.arraycopy(rawBytes, 0, authKey, offset, rawBytes.size)
        }

        val authKeyId = kdf.calculateAuthKeyId(authKey)
        return AuthKeyResult(authKey = authKey, authKeyId = authKeyId)
    }
}


package com.gargpadmakar.mtproto.crypto.security

import java.security.MessageDigest
import java.util.Arrays

/**
 * Encapsulates sensitive byte arrays (such as keys, IVs, and plaintext buffers) with
 * lifecycle-scoped zeroization, defensive copying, and constant-time comparisons.
 *
 * NOTE: As per JVM security architecture guidelines, complete in-memory zeroization is best-effort
 * due to JVM garbage collection, JIT compilation, and object relocation in memory.
 */
class SecureBytes private constructor(
    private var data: ByteArray?
) : AutoCloseable {

    private val lock = Any()
    private var isDestroyed = false

    val size: Int
        get() = synchronized(lock) {
            checkNotDestroyed()
            data!!.size
        }

    val isWiped: Boolean
        get() = synchronized(lock) { isDestroyed }

    /**
     * Executes an operation on a defensive copy of the raw bytes.
     * The temporary copy is wiped immediately in a finally block after [block] returns.
     */
    inline fun <R> withRawBytes(block: (ByteArray) -> R): R {
        val copy = copyRawBytes()
        return try {
            block(copy)
        } finally {
            wipe(copy)
        }
    }

    /**
     * Returns a fresh defensive copy of the contained bytes.
     * The caller is responsible for wiping the returned array when no longer needed.
     */
    fun copyRawBytes(): ByteArray {
        return synchronized(lock) {
            checkNotDestroyed()
            data!!.clone()
        }
    }

    /**
     * Slices the underlying bytes defensively.
     */
    fun slice(offset: Int, length: Int): SecureBytes {
        return synchronized(lock) {
            checkNotDestroyed()
            require(offset >= 0 && length >= 0 && offset + length <= data!!.size) {
                "Invalid slice range: offset=$offset, length=$length, total=${data!!.size}"
            }
            val slice = ByteArray(length)
            System.arraycopy(data!!, offset, slice, 0, length)
            SecureBytes(slice)
        }
    }

    /**
     * Compares the contained bytes with another byte array in constant time.
     */
    fun equalsConstantTime(other: ByteArray): Boolean {
        return synchronized(lock) {
            if (isDestroyed) return false
            MessageDigest.isEqual(data!!, other)
        }
    }

    /**
     * Compares two SecureBytes instances in constant time.
     */
    fun equalsConstantTime(other: SecureBytes): Boolean {
        return synchronized(lock) {
            if (isDestroyed || other.isWiped) return false
            other.withRawBytes { otherBytes ->
                MessageDigest.isEqual(data!!, otherBytes)
            }
        }
    }

    /**
     * Converts to lowercase hexadecimal representation.
     */
    fun toHex(): String {
        return withRawBytes { bytes ->
            val sb = StringBuilder(bytes.size * 2)
            for (b in bytes) {
                val v = b.toInt() and 0xFF
                if (v < 16) sb.append('0')
                sb.append(Integer.toHexString(v))
            }
            sb.toString()
        }
    }

    /**
     * Wipes the contained sensitive buffer by overwriting it with zeros.
     */
    fun wipe() {
        synchronized(lock) {
            if (!isDestroyed) {
                data?.let { wipe(it) }
                data = null
                isDestroyed = true
            }
        }
    }

    override fun close() {
        wipe()
    }

    private fun checkNotDestroyed() {
        check(!isDestroyed) { "SecureBytes buffer has already been wiped/destroyed." }
    }

    companion object {
        /**
         * Creates a SecureBytes instance by copying the provided byte array defensively.
         */
        fun from(source: ByteArray): SecureBytes {
            return SecureBytes(source.clone())
        }

        /**
         * Takes ownership of the provided byte array without copying.
         */
        fun wrap(source: ByteArray): SecureBytes {
            return SecureBytes(source)
        }

        /**
         * Creates a SecureBytes instance from a hexadecimal string.
         */
        fun fromHex(hexString: String): SecureBytes {
            val cleanHex = hexString.replace(" ", "").trim()
            require(cleanHex.length % 2 == 0) { "Hex string length must be even" }
            val len = cleanHex.length / 2
            val result = ByteArray(len)
            for (i in 0 until len) {
                val high = Character.digit(cleanHex[i * 2], 16)
                val low = Character.digit(cleanHex[i * 2 + 1], 16)
                require(high != -1 && low != -1) { "Invalid hex character in input" }
                result[i] = ((high shl 4) or low).toByte()
            }
            return SecureBytes(result)
        }

        /**
         * Best-effort zeroization of a byte array.
         */
        fun wipe(bytes: ByteArray?) {
            if (bytes != null) {
                Arrays.fill(bytes, 0.toByte())
            }
        }
    }
}


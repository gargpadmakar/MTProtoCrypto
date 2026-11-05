package com.gargpadmakar.mtproto.crypto.domain.model

/**
 * MTProto 2.0 message transmission direction.
 * Affects KDF offsets:
 * - [CLIENT_TO_SERVER]: x = 0, msg_key uses auth_key[88..119]
 * - [SERVER_TO_CLIENT]: x = 8, msg_key uses auth_key[96..127]
 */
enum class EncryptionDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}


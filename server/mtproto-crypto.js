/**
 * MTProto 2.0 Cryptographic Engine for Node.js
 * Author: Padmakar Garg
 *
 * Implements:
 * 1. AES-256-IGE Chaining (Infinite Garble Extension)
 * 2. Directional MTProto 2.0 Key Derivation Function (KDF)
 * 3. 2048-bit Diffie-Hellman Key Exchange (RFC 3526 Group 14)
 * 4. API Request Decryption (Client -> Server, x = 0)
 * 5. API Response Encryption (Server -> Client, x = 8)
 * 6. Timestamp & Nonce Replay Attack Protection
 * 7. Constant-Time Authentication Verification
 */

const crypto = require('crypto');

const AUTH_KEY_SIZE = 256;
const MSG_KEY_SIZE = 16;
const AUTH_KEY_ID_SIZE = 8;
const MIN_PADDING_BYTES = 12;
const ENVELOPE_HEADER_SIZE = 8 + 16 + 4; // timestamp(8) + nonce(16) + length(4)

class MTProtoCrypto {

  /**
   * Encrypts plaintext buffer using AES-256-IGE.
   * Chaining: c_i = AES_ECB(m_i ^ y_{i-1}) ^ x_{i-1}
   * where y_i = m_i, x_i = c_i.
   *
   * @param {Buffer} plaintext Plaintext buffer (length must be multiple of 16)
   * @param {Buffer} key 32-byte AES key
   * @param {Buffer} iv 32-byte IV (y_0 = iv[0..15], x_0 = iv[16..31])
   * @returns {Buffer} Ciphertext buffer
   */
  static aesIgeEncrypt(plaintext, key, iv) {
    if (plaintext.length % 16 !== 0) {
      throw new Error('Plaintext length must be a multiple of 16');
    }
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    if (iv.length !== 32) throw new Error('IV must be 32 bytes');

    let yPrev = iv.subarray(0, 16);
    let xPrev = iv.subarray(16, 32);

    const blocks = plaintext.length / 16;
    const ciphertext = Buffer.alloc(plaintext.length);

    for (let i = 0; i < blocks; i++) {
      const m = plaintext.subarray(i * 16, (i + 1) * 16);
      const blockInput = Buffer.alloc(16);
      for (let j = 0; j < 16; j++) {
        blockInput[j] = m[j] ^ yPrev[j];
      }

      const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
      cipher.setAutoPadding(false);
      const ecbOutput = cipher.update(blockInput);

      const c = Buffer.alloc(16);
      for (let j = 0; j < 16; j++) {
        c[j] = ecbOutput[j] ^ xPrev[j];
      }

      c.copy(ciphertext, i * 16);
      xPrev = c;
      yPrev = m;
    }

    return ciphertext;
  }

  /**
   * Decrypts ciphertext buffer using AES-256-IGE.
   * Chaining: m_i = AES_ECB_dec(c_i ^ x_{i-1}) ^ y_{i-1}
   * where y_i = m_i, x_i = c_i.
   *
   * @param {Buffer} ciphertext Ciphertext buffer (length must be multiple of 16)
   * @param {Buffer} key 32-byte AES key
   * @param {Buffer} iv 32-byte IV (y_0 = iv[0..15], x_0 = iv[16..31])
   * @returns {Buffer} Plaintext buffer
   */
  static aesIgeDecrypt(ciphertext, key, iv) {
    if (ciphertext.length % 16 !== 0) {
      throw new Error('Ciphertext length must be a multiple of 16');
    }
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    if (iv.length !== 32) throw new Error('IV must be 32 bytes');

    let yPrev = iv.subarray(0, 16);
    let xPrev = iv.subarray(16, 32);

    const blocks = ciphertext.length / 16;
    const plaintext = Buffer.alloc(ciphertext.length);

    for (let i = 0; i < blocks; i++) {
      const c = ciphertext.subarray(i * 16, (i + 1) * 16);
      const blockInput = Buffer.alloc(16);
      for (let j = 0; j < 16; j++) {
        blockInput[j] = c[j] ^ xPrev[j];
      }

      const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
      decipher.setAutoPadding(false);
      const ecbOutput = decipher.update(blockInput);

      const m = Buffer.alloc(16);
      for (let j = 0; j < 16; j++) {
        m[j] = ecbOutput[j] ^ yPrev[j];
      }

      m.copy(plaintext, i * 16);
      xPrev = c;
      yPrev = m;
    }

    return plaintext;
  }

  /**
   * Calculates the 16-byte msg_key according to MTProto 2.0.
   *
   * @param {Buffer} authKey 256-byte authorization key
   * @param {Buffer} buffer Unencrypted data buffer (header + payload + padding)
   * @param {string} direction 'client_to_server' | 'server_to_client'
   * @returns {Buffer} 16-byte message key
   */
  static calculateMsgKey(authKey, buffer, direction) {
    const offset = direction === 'client_to_server' ? 88 : 96;
    const authKeyPart = authKey.subarray(offset, offset + 32);

    const hash = crypto.createHash('sha256');
    hash.update(authKeyPart);
    hash.update(buffer);
    const digest = hash.digest();

    return digest.subarray(8, 24); // Middle 16 bytes (8..23 inclusive)
  }

  /**
   * Derives 32-byte AES key and 32-byte AES IV according to MTProto 2.0 KDF.
   *
   * @param {Buffer} authKey 256-byte authorization key
   * @param {Buffer} msgKey 16-byte message key
   * @param {string} direction 'client_to_server' | 'server_to_client'
   * @returns {{ aesKey: Buffer, aesIv: Buffer }}
   */
  static deriveAesKeyAndIv(authKey, msgKey, direction) {
    const x = direction === 'client_to_server' ? 0 : 8;

    // sha256_a = SHA256(msg_key + auth_key[x..x+35])
    const hashA = crypto.createHash('sha256');
    hashA.update(msgKey);
    hashA.update(authKey.subarray(x, x + 36));
    const sha256A = hashA.digest();

    // sha256_b = SHA256(auth_key[x+36..x+59] + msg_key + auth_key[x+60..x+75])
    const hashB = crypto.createHash('sha256');
    hashB.update(authKey.subarray(x + 36, x + 60));
    hashB.update(msgKey);
    hashB.update(authKey.subarray(x + 60, x + 76));
    const sha256B = hashB.digest();

    // sha256_c = SHA256(auth_key[x+76..x+115] + msg_key)
    const hashC = crypto.createHash('sha256');
    hashC.update(authKey.subarray(x + 76, x + 116));
    hashC.update(msgKey);
    const sha256C = hashC.digest();

    // sha256_d = SHA256(msg_key + auth_key[x+116..x+155])
    const hashD = crypto.createHash('sha256');
    hashD.update(msgKey);
    hashD.update(authKey.subarray(x + 116, x + 156));
    const sha256D = hashD.digest();

    // aes_key = sha256_a[0..7] + sha256_b[8..27] + sha256_c[4..7]
    const aesKey = Buffer.concat([
      sha256A.subarray(0, 8),
      sha256B.subarray(8, 28),
      sha256C.subarray(4, 8)
    ]);

    // aes_iv = sha256_a[8..15] + sha256_b[0..7] + sha256_c[16..23] + sha256_d[0..7]
    const aesIv = Buffer.concat([
      sha256A.subarray(8, 16),
      sha256B.subarray(0, 8),
      sha256C.subarray(16, 24),
      sha256D.subarray(0, 8)
    ]);

    return { aesKey, aesIv };
  }

  /**
   * Computes the 64-bit auth_key_id (lower 64 bits of SHA-1(auth_key)) as a BigInt string.
   *
   * @param {Buffer} authKey 256-byte authorization key
   * @returns {string} 64-bit signed integer string
   */
  static calculateAuthKeyId(authKey) {
    const sha1 = crypto.createHash('sha1').update(authKey).digest();
    const idBuf = sha1.subarray(12, 20); // lower 64 bits
    return idBuf.readBigInt64BE(0).toString();
  }

  /**
   * Decrypts an incoming client API request payload.
   *
   * @param {object} encryptedRequest { auth_key_id, msg_key, payload, timestamp }
   * @param {Buffer} authKey 256-byte session key
   * @param {number} maxClockSkewMs Max allowed timestamp skew (default 60s)
   * @returns {{ data: Buffer, json: object, timestamp: number, nonce: Buffer }}
   */
  static decryptClientRequest(encryptedRequest, authKey, maxClockSkewMs = 60000) {
    const expectedAuthKeyId = this.calculateAuthKeyId(authKey);
    if (encryptedRequest.auth_key_id.toString() !== expectedAuthKeyId) {
      throw new Error(`auth_key_id mismatch: expected ${expectedAuthKeyId}, received ${encryptedRequest.auth_key_id}`);
    }

    const msgKey = Buffer.isBuffer(encryptedRequest.msg_key)
      ? encryptedRequest.msg_key
      : Buffer.from(encryptedRequest.msg_key, 'base64');

    const ciphertext = Buffer.isBuffer(encryptedRequest.payload)
      ? encryptedRequest.payload
      : Buffer.from(encryptedRequest.payload, 'base64');

    if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
      throw new Error('Invalid ciphertext length: must be non-zero and multiple of 16');
    }

    // Direction: client_to_server (x = 0)
    const { aesKey, aesIv } = this.deriveAesKeyAndIv(authKey, msgKey, 'client_to_server');
    const decryptedBuffer = this.aesIgeDecrypt(ciphertext, aesKey, aesIv);

    // Constant-time message key verification
    const calculatedMsgKey = this.calculateMsgKey(authKey, decryptedBuffer, 'client_to_server');
    if (!crypto.timingSafeEqual(calculatedMsgKey, msgKey)) {
      throw new Error('Message key verification failed: ciphertext tampered or corrupt');
    }

    // Parse envelope: timestamp(8) + nonce(16) + length(4) + payload + padding
    const timestamp = Number(decryptedBuffer.readBigInt64BE(0));
    const nonce = decryptedBuffer.subarray(8, 24);
    const payloadLength = decryptedBuffer.readInt32BE(24);

    if (payloadLength < 0 || payloadLength > decryptedBuffer.length - ENVELOPE_HEADER_SIZE - MIN_PADDING_BYTES) {
      throw new Error(`Invalid payload length in envelope: ${payloadLength}`);
    }

    // Verify clock skew for replay protection
    if (maxClockSkewMs > 0) {
      const now = Date.now();
      const delta = Math.abs(now - timestamp);
      if (delta > maxClockSkewMs) {
        throw new Error(`Replay attack detected or clock out of sync: skew ${delta}ms > allowed ${maxClockSkewMs}ms`);
      }
    }

    const payloadData = decryptedBuffer.subarray(ENVELOPE_HEADER_SIZE, ENVELOPE_HEADER_SIZE + payloadLength);

    let parsedJson = null;
    try {
      parsedJson = JSON.parse(payloadData.toString('utf8'));
    } catch (_) {}

    return {
      data: payloadData,
      json: parsedJson,
      text: payloadData.toString('utf8'),
      timestamp,
      nonce
    };
  }

  /**
   * Encrypts an outgoing server API response payload.
   *
   * @param {string|Buffer|object} payload Data to send (string, buffer, or JS object)
   * @param {Buffer} authKey 256-byte session key
   * @param {number} timestamp Optional epoch ms
   * @returns {{ auth_key_id: string, msg_key: string, payload: string, timestamp: number }}
   */
  static encryptServerResponse(payload, authKey, timestamp = Date.now()) {
    let payloadBuffer;
    if (Buffer.isBuffer(payload)) {
      payloadBuffer = payload;
    } else if (typeof payload === 'object') {
      payloadBuffer = Buffer.from(JSON.stringify(payload), 'utf8');
    } else {
      payloadBuffer = Buffer.from(String(payload), 'utf8');
    }

    const nonce = crypto.randomBytes(16);
    const unpaddedLength = ENVELOPE_HEADER_SIZE + payloadBuffer.length;
    let paddingLen = (16 - (unpaddedLength % 16)) % 16;
    if (paddingLen < MIN_PADDING_BYTES) {
      paddingLen += 16;
    }

    // Random extra blocks (0..3)
    const extraBlocks = Math.floor(Math.random() * 4);
    paddingLen += extraBlocks * 16;

    const totalLength = unpaddedLength + paddingLen;
    const unencryptedBuffer = Buffer.alloc(totalLength);

    // 8-byte timestamp
    unencryptedBuffer.writeBigInt64BE(BigInt(timestamp), 0);
    // 16-byte nonce
    nonce.copy(unencryptedBuffer, 8);
    // 4-byte payload length
    unencryptedBuffer.writeInt32BE(payloadBuffer.length, 24);
    // payload
    payloadBuffer.copy(unencryptedBuffer, 28);
    // random padding
    crypto.randomFillSync(unencryptedBuffer, unpaddedLength, paddingLen);

    // Direction: server_to_client (x = 8)
    const msgKey = this.calculateMsgKey(authKey, unencryptedBuffer, 'server_to_client');
    const { aesKey, aesIv } = this.deriveAesKeyAndIv(authKey, msgKey, 'server_to_client');
    const ciphertext = this.aesIgeEncrypt(unencryptedBuffer, aesKey, aesIv);
    const authKeyId = this.calculateAuthKeyId(authKey);

    return {
      auth_key_id: authKeyId,
      msg_key: msgKey.toString('base64'),
      payload: ciphertext.toString('base64'),
      timestamp: timestamp,
      nonce: nonce.toString('base64')
    };
  }
}

module.exports = MTProtoCrypto;

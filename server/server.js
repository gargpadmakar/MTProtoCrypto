/**
 * Production-Ready Express.js Server with MTProto 2.0 API Payload Encryption
 * Author: Padmakar Garg
 *
 * Features:
 * 1. Zero-Static-Key Security: Dynamic 2048-bit Diffie-Hellman Handshake.
 * 2. Reverse-Engineering Immunity: No static AES keys in Android APK or Server.
 * 3. Directional MTProto 2.0 KDF (Client-to-Server vs Server-to-Client).
 * 4. AES-256-IGE Chaining with Anti-Traffic Analysis Random Padding.
 * 5. Replay Attack Detection with Timestamp & Nonce Validation.
 */

const express = require('express');
const crypto = require('crypto');
const MTProtoCrypto = require('./mtproto-crypto');

const app = express();
app.use(express.json());

// In-Memory Secure Session Storage (Use Redis in multi-instance production)
// Key: auth_key_id string -> Value: { authKey: Buffer, createdAt: number }
const sessionStore = new Map();

// RFC 3526 Group 14 2048-bit MODP Prime & Generator (g = 2)
// This matches standard MTProto DH parameters
const dhGroup = crypto.getDiffieHellman('modp14');

/**
 * Endpoint 1: Ephemeral Diffie-Hellman 2048-bit Handshake
 *
 * Client sends its public key A = g^a mod p.
 * Server generates its public key B = g^b mod p and computes shared secret K = A^b mod p.
 * The 256-byte auth_key is established dynamically in memory on both ends.
 * ZERO static keys exist in the Android APK!
 */
app.post('/api/auth/handshake', (req, res) => {
  try {
    const { client_public_key } = req.body;
    if (!client_public_key) {
      return res.status(400).json({ error: 'client_public_key is required (hex or base64)' });
    }

    const clientKeyBuf = Buffer.from(
      client_public_key,
      client_public_key.length === 512 ? 'hex' : 'base64'
    );

    // Create server DH instance using RFC 3526 Group 14
    const serverDh = crypto.createDiffieHellman(dhGroup.getPrime(), dhGroup.getGenerator());
    serverDh.generateKeys();

    const serverPublicKey = serverDh.getPublicKey();
    const sharedSecret = serverDh.computeSecret(clientKeyBuf);

    // Ensure 256 bytes (pad with leading zeros if necessary)
    let authKey = sharedSecret;
    if (authKey.length < 256) {
      const padded = Buffer.alloc(256, 0);
      authKey.copy(padded, 256 - authKey.length);
      authKey = padded;
    } else if (authKey.length > 256) {
      authKey = authKey.subarray(authKey.length - 256);
    }

    const authKeyId = MTProtoCrypto.calculateAuthKeyId(authKey);

    // Store session in memory
    sessionStore.set(authKeyId, {
      authKey,
      createdAt: Date.now()
    });

    console.log(`[Handshake] New secure session established: auth_key_id=${authKeyId}`);

    return res.json({
      status: 'ok',
      auth_key_id: authKeyId,
      server_public_key: serverPublicKey.toString('base64')
    });
  } catch (error) {
    console.error('[Handshake Error]', error);
    return res.status(500).json({ error: error.message });
  }
});

/**
 * Endpoint 2: Secure Encrypted API Endpoint
 *
 * Accepts encrypted client request: { auth_key_id, msg_key, payload, timestamp }
 * Decrypts with Client-to-Server KDF (x = 0).
 * Validates timestamp & nonce (anti-replay).
 * Executes business logic.
 * Encrypts response with Server-to-Client KDF (x = 8).
 */
app.post('/api/secure-data', (req, res) => {
  try {
    const { auth_key_id, msg_key, payload, timestamp } = req.body;

    if (!auth_key_id || !msg_key || !payload) {
      return res.status(400).json({ error: 'Missing encrypted envelope fields' });
    }

    const session = sessionStore.get(auth_key_id.toString());
    if (!session) {
      return res.status(401).json({
        error: 'Session expired or unknown auth_key_id. Re-negotiate DH handshake.'
      });
    }

    // Decrypt incoming client payload (max 60 seconds clock skew allowed)
    const decrypted = MTProtoCrypto.decryptClientRequest(
      req.body,
      session.authKey,
      60000
    );

    console.log(`[Decrypted Request] authKeyId=${auth_key_id}:`, decrypted.json || decrypted.text);

    // --- Business Logic Execution ---
    const clientData = decrypted.json || { message: decrypted.text };
    const responseData = {
      status: 'success',
      receivedAt: new Date().toISOString(),
      processedData: clientData,
      serverSecretMessage: 'This response was securely encrypted using MTProto 2.0 AES-IGE!'
    };

    // Encrypt outgoing response payload (Server -> Client, x = 8)
    const encryptedResponse = MTProtoCrypto.encryptServerResponse(
      responseData,
      session.authKey
    );

    return res.json(encryptedResponse);
  } catch (error) {
    console.error('[Decryption Error]', error.message);
    return res.status(400).json({ error: `Decryption/Authentication failed: ${error.message}` });
  }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`MTProto 2.0 Secure API Server running on port ${PORT}`);
    console.log(`- Endpoints:`);
    console.log(`  POST http://localhost:${PORT}/api/auth/handshake`);
    console.log(`  POST http://localhost:${PORT}/api/secure-data`);
    console.log(`====================================================`);
  });
}

module.exports = { app, sessionStore };


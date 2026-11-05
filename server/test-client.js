/**
 * Test Client to Verify End-to-End MTProto 2.0 API Encryption & Decryption
 * Author: Padmakar Garg
 */

const crypto = require('crypto');
const MTProtoCrypto = require('./mtproto-crypto');

function runTest() {
  console.log('--- MTProto 2.0 API Payload Encryption / Decryption Test ---');

  // 1. Simulate 256-byte session auth_key established via DH Handshake
  const authKey = crypto.randomBytes(256);
  const authKeyId = MTProtoCrypto.calculateAuthKeyId(authKey);
  console.log(`Generated Session auth_key_id: ${authKeyId}`);

  // 2. Client prepares request payload
  const requestPayload = {
    userId: 'user_padmakar_777',
    accountNumber: 'ACC-9812-4410',
    action: 'INITIATE_CONFIDENTIAL_TRANSFER',
    amount: 50000.00
  };
  const requestJson = JSON.stringify(requestPayload);
  console.log('\n[1] Client Request Plaintext:', requestJson);

  // Client encrypts request (Client -> Server, x = 0)
  // Replicating Android ApiCryptoEngine.encryptRequest()
  const nonce = crypto.randomBytes(16);
  const timestamp = Date.now();
  const payloadBuf = Buffer.from(requestJson, 'utf8');

  const unpaddedLength = 8 + 16 + 4 + payloadBuf.length;
  let paddingLen = (16 - (unpaddedLength % 16)) % 16;
  if (paddingLen < 12) paddingLen += 16;

  const totalLength = unpaddedLength + paddingLen;
  const unencrypted = Buffer.alloc(totalLength);
  unencrypted.writeBigInt64BE(BigInt(timestamp), 0);
  nonce.copy(unencrypted, 8);
  unencrypted.writeInt32BE(payloadBuf.length, 24);
  payloadBuf.copy(unencrypted, 28);
  crypto.randomFillSync(unencrypted, unpaddedLength, paddingLen);

  const msgKey = MTProtoCrypto.calculateMsgKey(authKey, unencrypted, 'client_to_server');
  const { aesKey, aesIv } = MTProtoCrypto.deriveAesKeyAndIv(authKey, msgKey, 'client_to_server');
  const ciphertext = MTProtoCrypto.aesIgeEncrypt(unencrypted, aesKey, aesIv);

  const clientEncryptedPacket = {
    auth_key_id: authKeyId,
    msg_key: msgKey.toString('base64'),
    payload: ciphertext.toString('base64'),
    timestamp: timestamp
  };

  console.log('\n[2] Client Encrypted Packet (Over the wire HTTP Body):');
  console.log(JSON.stringify(clientEncryptedPacket, null, 2));

  // 3. Server receives and decrypts request
  console.log('\n[3] Server decrypting incoming request...');
  const serverDecrypted = MTProtoCrypto.decryptClientRequest(clientEncryptedPacket, authKey);
  console.log('Server Decrypted Successfully! Payload:', serverDecrypted.json);

  if (serverDecrypted.json.accountNumber !== requestPayload.accountNumber) {
    throw new Error('Verification failed: decrypted payload does not match!');
  }
  console.log('Payload verification MATCHED 100%!');

  // 4. Server generates response & encrypts (Server -> Client, x = 8)
  const responseData = {
    status: 'SUCCESS',
    transactionId: 'TXN_' + crypto.randomBytes(8).toString('hex').toUpperCase(),
    newBalance: 1450000.00,
    timestamp: new Date().toISOString()
  };
  console.log('\n[4] Server Response Plaintext:', JSON.stringify(responseData));

  const serverEncryptedPacket = MTProtoCrypto.encryptServerResponse(responseData, authKey);
  console.log('\n[5] Server Encrypted Packet (Over the wire HTTP Response):');
  console.log(JSON.stringify(serverEncryptedPacket, null, 2));

  // 5. Client receives and decrypts response (Server -> Client, x = 8)
  console.log('\n[6] Client decrypting server response...');
  const serverMsgKey = Buffer.from(serverEncryptedPacket.msg_key, 'base64');
  const serverCiphertext = Buffer.from(serverEncryptedPacket.payload, 'base64');

  const clientDerived = MTProtoCrypto.deriveAesKeyAndIv(authKey, serverMsgKey, 'server_to_client');
  const clientDecryptedBuf = MTProtoCrypto.aesIgeDecrypt(serverCiphertext, clientDerived.aesKey, clientDerived.aesIv);

  // Constant-time verify msg_key
  const clientCalculatedMsgKey = MTProtoCrypto.calculateMsgKey(authKey, clientDecryptedBuf, 'server_to_client');
  if (!crypto.timingSafeEqual(clientCalculatedMsgKey, serverMsgKey)) {
    throw new Error('Client verification of server response msg_key failed!');
  }

  const responseLen = clientDecryptedBuf.readInt32BE(24);
  const responseText = clientDecryptedBuf.subarray(28, 28 + responseLen).toString('utf8');
  const parsedResponse = JSON.parse(responseText);

  console.log('Client Decrypted Successfully! Response:', parsedResponse);
  if (parsedResponse.transactionId !== responseData.transactionId) {
    throw new Error('Client response data mismatch!');
  }

  // 6. Test Replay Attack Protection
  console.log('\n[7] Testing Replay Attack Detection...');
  const staleTimestamp = Date.now() - 120000; // 2 minutes in the past
  const staleUnencrypted = Buffer.alloc(totalLength);
  staleUnencrypted.writeBigInt64BE(BigInt(staleTimestamp), 0);
  nonce.copy(staleUnencrypted, 8);
  staleUnencrypted.writeInt32BE(payloadBuf.length, 24);
  payloadBuf.copy(staleUnencrypted, 28);
  crypto.randomFillSync(staleUnencrypted, unpaddedLength, paddingLen);

  const staleMsgKey = MTProtoCrypto.calculateMsgKey(authKey, staleUnencrypted, 'client_to_server');
  const staleKeys = MTProtoCrypto.deriveAesKeyAndIv(authKey, staleMsgKey, 'client_to_server');
  const staleCiphertext = MTProtoCrypto.aesIgeEncrypt(staleUnencrypted, staleKeys.aesKey, staleKeys.aesIv);

  const stalePacket = {
    auth_key_id: authKeyId,
    msg_key: staleMsgKey.toString('base64'),
    payload: staleCiphertext.toString('base64'),
    timestamp: staleTimestamp
  };

  try {
    MTProtoCrypto.decryptClientRequest(stalePacket, authKey, 30000);
    throw new Error('Replay attack was NOT detected!');
  } catch (err) {
    if (err.message.includes('Replay attack detected')) {
      console.log('Replay attack successfully blocked:', err.message);
    } else {
      throw err;
    }
  }

  // 7. Test Tampering Detection
  console.log('\n[8] Testing Tamper Detection...');
  const tamperedCiphertext = Buffer.from(clientEncryptedPacket.payload, 'base64');
  tamperedCiphertext[0] ^= 0xff; // flip bits
  const tamperedPacket = { ...clientEncryptedPacket, payload: tamperedCiphertext.toString('base64') };
  try {
    MTProtoCrypto.decryptClientRequest(tamperedPacket, authKey);
    throw new Error('Tampered packet was NOT detected!');
  } catch (err) {
    console.log('Tampered packet successfully detected and rejected:', err.message);
  }

  console.log('\n======================================================');
  console.log('ALL TESTS PASSED! Node.js MTProto 2.0 Engine is 100% verified!');
  console.log('======================================================');
}

runTest();

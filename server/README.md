# MTProto 2.0 Secure API Server (Node.js)

Author: **Padmakar Garg**  
Specification: **MTProto 2.0 Dual-Directional Key Derivation & AES-256-IGE Chaining**

---

## Overview

This directory contains the production-ready Node.js backend implementation corresponding to the **MTProtoCrypto** Android SDK. It provides:

- **End-to-End API Request Decryption (Client -> Server, offset $x = 0$)**
- **End-to-End API Response Encryption (Server -> Client, offset $x = 8$)**
- **Zero Static Keys in Android APK (Dynamic 2048-bit Diffie-Hellman Handshake)**
- **Replay Attack & Tampering Protection (Timestamp, Nonce, Constant-Time SHA-256 verification)**
- **Anti-Reverse Engineering Defense**

---

## Directory Contents

| File | Purpose |
| :--- | :--- |
| `mtproto-crypto.js` | Pure Node.js cryptographic engine implementing AES-256-IGE, MTProto 2.0 KDF, and envelope parsing using standard `crypto` module. Zero external cryptographic dependencies. |
| `server.js` | Express.js REST server providing `/api/auth/handshake` (DH exchange) and `/api/secure-data` (encrypted payload processing). |
| `test-client.js` | Standalone verification test demonstrating client request encryption, server decryption, server response encryption, and replay defense. |
| `package.json` | Project configuration and scripts. |

---

## Quickstart

### 1. Run Verification Test
You can run the cryptographic test immediately without installing dependencies (uses Node.js native `crypto`):

```bash
node test-client.js
```

### 2. Start Express Server
To run the HTTP REST server:

```bash
npm install
npm start
```

The server starts on `http://localhost:3000`.

---

## API Endpoints

### 1. Ephemeral Diffie-Hellman Handshake
**`POST /api/auth/handshake`**

Negotiates an ephemeral 2048-bit session key between Android and the Node.js server. **No hardcoded secret keys are present in the Android APK.**

- **Request Body:**
  ```json
  {
    "client_public_key": "<Base64_or_Hex_2048bit_DH_Public_Key>"
  }
  ```
- **Response Body:**
  ```json
  {
    "status": "ok",
    "auth_key_id": "-3288831517649641508",
    "server_public_key": "<Base64_2048bit_DH_Public_Key>"
  }
  ```

---

### 2. Secure Encrypted Endpoint
**`POST /api/secure-data`**

Accepts MTProto 2.0 encrypted API payloads, decrypts and validates them, processes business logic, and returns an encrypted response.

- **Encrypted Request Body (From Android App):**
  ```json
  {
    "auth_key_id": "-3288831517649641508",
    "msg_key": "wQBYuRm+78vWb6uOkpwdRw==",
    "payload": "Fi+0n9Hfnz88nlfjyW6IqEsZsihLHcQ9VXWZBoVilQo35c...",
    "timestamp": 1793871463230
  }
  ```

- **Encrypted Response Body (To Android App):**
  ```json
  {
    "auth_key_id": "-3288831517649641508",
    "msg_key": "MuF2XHR7lKPO0+n2mazX2A==",
    "payload": "kewakOIM4cmkLP+/RptK2jleDlUgyEhho5FS+2Zaw3OjY...",
    "timestamp": 1793871463235,
    "nonce": "raLAdw0sB+8iDnt2J3U0uQ=="
  }
  ```

---

## Anti-Reverse Engineering Architecture

### Why Traditional API Obfuscation Fails
Most apps attempt to hide static AES keys inside:
- `BuildConfig` constants
- Java/Kotlin strings
- C/C++ NDK shared libraries (`.so` files)

These approaches fail against modern reverse engineering tools:
- **JADX / APKTool:** Easily decompile strings and byte arrays.
- **IDA Pro / Ghidra:** Disassemble `.so` binaries and extract keys from `.rodata`.
- **Frida / Objection:** Hook `Cipher.init()` or memory scan (`Memory.scan`) to dump the static key at runtime.

### How MTProtoCrypto Solves This
1. **Zero Static Keys in APK:** The encryption key is mathematically generated at runtime via 2048-bit Diffie-Hellman handshake over TLS. Even if the entire APK is decompiled to source code, there is no key to find.
2. **Directional Ephemeral KDF:** Request payloads use Client-to-Server derivation ($x = 0$); response payloads use Server-to-Client derivation ($x = 8$). A compromised request key cannot decrypt responses.
3. **Replay Window Enforcement:** Every payload contains a dynamic 64-bit timestamp and 128-bit cryptographic nonce. The server rejects any replayed packets or packets outside the allowed clock skew window ($< 60$ seconds).
4. **Anti-Traffic Analysis Padding:** MTProto 2.0 injects 12 to 1024 random padding bytes, masking payload length and preventing statistical traffic analysis.
5. **Memory Sanitization:** Byte arrays and keys are immediately zeroized in-memory after use.

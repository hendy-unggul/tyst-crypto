# tyst-crypto

The cryptographic engine powering [TYST](https://tyst.site) — zero-knowledge ephemeral messaging.

This is the complete code that runs on your device when you send a message via TYST. The server never sees plaintext. Verify it yourself.

---

## Protocol

```
Key exchange:    ECDH P-256  (ephemeral keypair — new pair per message, never reused)
Encryption:      AES-GCM 256-bit
Key derivation:  HKDF-SHA256 (salt: 32 zero bytes · info: "whisper-v2")
Padding:         256-byte blocks (message size does not leak)
IV:              12-byte random (crypto.getRandomValues)
```

## Wire format

```
base64(iv) : base64(ephemeral_pubkey_jwk) : base64(ciphertext)
```

Three colon-separated, base64-encoded fields. The ephemeral public key is embedded in the ciphertext — the recipient needs no prior key exchange.

---

## How it works

```
SENDER                              RECIPIENT
──────                              ─────────
1. Generate ephemeral ECDH keypair
2. Fetch recipient's stored pubkey
3. ECDH(eph_priv, recipient_pub)
   → shared secret
4. HKDF(shared_secret)
   → AES-256 key
5. Pad plaintext to 256-byte block
6. AES-GCM encrypt(plaintext, IV)
7. Transmit:
   base64(IV)
   + base64(eph_pub_jwk)           → stored as ciphertext on server
   + base64(ciphertext)
                                    8. Parse wire format
                                    9. Import eph_pub
                                   10. ECDH(recipient_priv, eph_pub)
                                       → same shared secret
                                   11. HKDF → same AES key
                                   12. AES-GCM decrypt
                                   13. Unpad → plaintext
```

The server stores only the wire-format ciphertext. It cannot decrypt it — the recipient's private key never leaves their device.

---

## Security properties

| Property | Status | Notes |
|---|---|---|
| Forward secrecy | ✓ | Ephemeral keypair per message |
| Message confidentiality | ✓ | AES-GCM 256-bit |
| Sender anonymity | ✓ | No sender identity in ciphertext |
| Ciphertext integrity | ✓ | AES-GCM authentication tag |
| Size obfuscation | ✓ | 256-byte block padding |
| Post-quantum | ✗ | P-256 is not quantum-resistant |
| Key storage | device only | localStorage — see threat model |

---

## Known limitations

**This code does not protect against:**

- **Device compromise** — private key is stored in `localStorage`. Anyone with physical or remote access to your device can extract it.
- **Recipient betrayal** — the recipient can screenshot or copy any message before it self-destructs.
- **Quantum adversaries** — ECDH P-256 is not post-quantum secure.
- **Network-level surveillance** — this library encrypts content, not metadata. Use Tor for network anonymity.

See the full [TYST threat model](https://tyst.site/threat-model) for a complete assessment.

---

## Run the tests

### Browser

```html
<script src="crypto.js"></script>
<script src="crypto.test.js"></script>
<!-- Open browser console — tests run automatically on load -->
```

### Node.js (v18+)

```js
const { webcrypto } = require('crypto');
globalThis.crypto = webcrypto;

// Load crypto.js (sets globalThis.TYSTCrypto)
require('./crypto.js');

const { runTests } = require('./crypto.test.js');
runTests().then(({ passed, failed }) => {
  process.exit(failed > 0 ? 1 : 0);
});
```

Expected output:
```
── tyst-crypto test results ──────────────────
  ✓ PASS  keypair: kty is EC
  ✓ PASS  keypair: curve is P-256
  ✓ PASS  roundtrip: decrypt(encrypt(msg)) === msg
  ✓ PASS  ephemeral: two encryptions of same msg produce different ciphertext
  ✓ PASS  wire format: exactly 3 colon-separated parts
  ✓ PASS  padding: all messages pad to multiple of 256
  ✓ PASS  wrong key: decrypt with wrong private key returns error string
  ✓ PASS  tamper detection: AES-GCM rejects modified ciphertext
  ✓ PASS  unicode: full unicode roundtrip
  ✓ PASS  max length: 500-char message roundtrip
──────────────────────────────────────────────
  10 passed, 0 failed
```

---

## Audit

This library has not yet undergone a formal third-party audit.

We invite independent review:

- **Non-critical findings** — open a GitHub issue
- **Critical vulnerabilities** — email `security@tyst.site`  
- **Response time** — 48 hours for critical, 7 days for non-critical

We do not offer monetary bounties at this stage. Confirmed findings will be credited in a public hall of fame at `tyst.site/security`.

---

## Relationship to TYST app

This library is the complete cryptographic layer used in production at `tyst.site`. The server-side code (relay, key storage, message delivery) is not published here — but it handles only ciphertext and is never in a position to read message content.

The relevant security guarantee — that the server cannot read your messages — is verifiable entirely from this library and the browser's developer tools.

---

## License

MIT — use freely, audit freely, fork freely.

```
Copyright (c) 2026 TYST
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software to deal in the Software without restriction.
```

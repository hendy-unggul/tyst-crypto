/**
 * tyst-crypto — test vectors
 *
 * Run in browser console or Node.js (requires WebCrypto).
 * Node: node --experimental-vm-modules crypto.test.js
 *
 * All tests are self-contained and runnable without a test framework.
 */

async function runTests() {
  'use strict';

  const results = [];
  let passed = 0, failed = 0;

  function assert(condition, name, detail = '') {
    if (condition) {
      results.push({ status: 'PASS', name });
      passed++;
    } else {
      results.push({ status: 'FAIL', name, detail });
      failed++;
    }
  }

  // ── TEST 1: Keypair generation ──────────────────────────────────
  {
    const kp = await TYSTCrypto.generateKeypair();
    assert(kp.pub.kty === 'EC',          'keypair: kty is EC');
    assert(kp.pub.crv === 'P-256',       'keypair: curve is P-256');
    assert(typeof kp.pub.x === 'string', 'keypair: pub has x coordinate');
    assert(typeof kp.pub.y === 'string', 'keypair: pub has y coordinate');
    assert(!('d' in kp.pub),             'keypair: pub does NOT contain private key (d)');
    assert(typeof kp.priv.d === 'string','keypair: priv contains private component (d)');
  }

  // ── TEST 2: Encrypt → Decrypt roundtrip ────────────────────────
  {
    const kp        = await TYSTCrypto.generateKeypair();
    const plaintext = 'hello, this is a secret message';
    const encrypted = await TYSTCrypto.encrypt(plaintext, kp.pub);
    const decrypted = await TYSTCrypto.decrypt(encrypted, kp.priv);
    assert(decrypted === plaintext, 'roundtrip: decrypt(encrypt(msg)) === msg');
  }

  // ── TEST 3: Ephemeral keypair — each encryption is unique ───────
  {
    const kp  = await TYSTCrypto.generateKeypair();
    const msg = 'same message';
    const e1  = await TYSTCrypto.encrypt(msg, kp.pub);
    const e2  = await TYSTCrypto.encrypt(msg, kp.pub);
    assert(e1 !== e2, 'ephemeral: two encryptions of same msg produce different ciphertext');
    // But both decrypt correctly
    const d1 = await TYSTCrypto.decrypt(e1, kp.priv);
    const d2 = await TYSTCrypto.decrypt(e2, kp.priv);
    assert(d1 === msg && d2 === msg, 'ephemeral: both ciphertexts decrypt correctly');
  }

  // ── TEST 4: Wire format structure ───────────────────────────────
  {
    const kp        = await TYSTCrypto.generateKeypair();
    const encrypted = await TYSTCrypto.encrypt('test', kp.pub);
    const parts     = encrypted.split(':');
    assert(parts.length === 3, 'wire format: exactly 3 colon-separated parts');
    // Part 0: IV (12 bytes = 16 base64 chars)
    const iv = atob(parts[0]);
    assert(iv.length === 12, 'wire format: IV is 12 bytes');
    // Part 1: ephemeral pubkey JWK
    const ephPub = JSON.parse(atob(parts[1]));
    assert(ephPub.kty === 'EC' && ephPub.crv === 'P-256', 'wire format: ephemeral pubkey is P-256');
    assert(!('d' in ephPub), 'wire format: ephemeral pubkey has no private component');
  }

  // ── TEST 5: Padding — all ciphertexts are 256-byte multiples ────
  {
    const kp = await TYSTCrypto.generateKeypair();
    const testMessages = ['a', 'hello', 'x'.repeat(255), 'x'.repeat(256), 'x'.repeat(257)];
    for (const msg of testMessages) {
      const padded = TYSTCrypto._pad(msg);
      assert(
        padded.length % TYSTCrypto._BLOCK_SIZE === 0,
        `padding: "${msg.slice(0,10)}..." pads to multiple of ${TYSTCrypto._BLOCK_SIZE}`
      );
    }
  }

  // ── TEST 6: Padding roundtrip ───────────────────────────────────
  {
    const messages = ['hello', 'x'.repeat(255), 'x'.repeat(256), 'unicode: 你好'];
    for (const msg of messages) {
      const padded   = TYSTCrypto._pad(msg);
      const unpadded = TYSTCrypto._unpad(padded);
      assert(unpadded === msg, `pad/unpad roundtrip: "${msg.slice(0,20)}..."`);
    }
  }

  // ── TEST 7: Wrong key cannot decrypt ────────────────────────────
  {
    const kp1       = await TYSTCrypto.generateKeypair();
    const kp2       = await TYSTCrypto.generateKeypair();
    const encrypted = await TYSTCrypto.encrypt('secret', kp1.pub);
    const decrypted = await TYSTCrypto.decrypt(encrypted, kp2.priv); // wrong key
    assert(
      decrypted === '[could not decrypt]',
      'wrong key: decrypt with wrong private key returns error string'
    );
  }

  // ── TEST 8: Tampered ciphertext is rejected ─────────────────────
  {
    const kp        = await TYSTCrypto.generateKeypair();
    const encrypted = await TYSTCrypto.encrypt('authentic message', kp.pub);
    // Tamper: flip a byte in ciphertext
    const parts     = encrypted.split(':');
    const ctBytes   = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0));
    ctBytes[ctBytes.length - 1] ^= 0xFF; // flip last byte
    const tampered  = parts[0] + ':' + parts[1] + ':' + btoa(String.fromCharCode(...ctBytes));
    const decrypted = await TYSTCrypto.decrypt(tampered, kp.priv);
    assert(
      decrypted === '[could not decrypt]',
      'tamper detection: AES-GCM rejects modified ciphertext'
    );
  }

  // ── TEST 9: Unicode messages ─────────────────────────────────────
  {
    const kp        = await TYSTCrypto.generateKeypair();
    const unicode   = '你好世界 — Привет мир — مرحبا بالعالم 🔒';
    const encrypted = await TYSTCrypto.encrypt(unicode, kp.pub);
    const decrypted = await TYSTCrypto.decrypt(encrypted, kp.priv);
    assert(decrypted === unicode, 'unicode: full unicode roundtrip');
  }

  // ── TEST 10: Max length message ──────────────────────────────────
  {
    const kp        = await TYSTCrypto.generateKeypair();
    const maxMsg    = 'a'.repeat(500); // TYST max
    const encrypted = await TYSTCrypto.encrypt(maxMsg, kp.pub);
    const decrypted = await TYSTCrypto.decrypt(encrypted, kp.priv);
    assert(decrypted === maxMsg, 'max length: 500-char message roundtrip');
  }

  // ── Results ──────────────────────────────────────────────────────
  console.log('\n── tyst-crypto test results ──────────────────');
  results.forEach(r => {
    const icon = r.status === 'PASS' ? '✓' : '✗';
    console.log(`  ${icon} ${r.status}  ${r.name}`);
    if (r.detail) console.log(`       detail: ${r.detail}`);
  });
  console.log(`──────────────────────────────────────────────`);
  console.log(`  ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('  all tests passed ✓');
  } else {
    console.log('  FAILURES DETECTED ✗');
  }
  return { passed, failed };
}

// Auto-run if in browser
if (typeof window !== 'undefined') {
  window.addEventListener('load', () => {
    if (window.TYSTCrypto) {
      runTests().catch(console.error);
    } else {
      console.error('TYSTCrypto not found — load crypto.js first');
    }
  });
}

if (typeof module !== 'undefined') module.exports = { runTests };

/**
 * tyst-crypto
 *
 * Standalone cryptographic engine used by TYST (https://tyst.site).
 * Zero dependencies. Runs in any modern browser or Node.js (via WebCrypto API).
 *
 * Protocol:
 *   Key exchange:   ECDH P-256 (ephemeral keypair per message — never reused)
 *   Encryption:     AES-GCM 256-bit
 *   Key derivation: HKDF-SHA256 (salt: 32 zero bytes, info: "whisper-v2")
 *   Padding:        256-byte block padding (message size does not leak)
 *   IV:             12-byte random (crypto.getRandomValues)
 *
 * Wire format (base64-encoded, colon-separated):
 *   base64(iv) : base64(ephemeral_pubkey_jwk) : base64(ciphertext)
 *
 * TYST — https://tyst.site
 * License: MIT
 */

const TYSTCrypto = (() => {
  'use strict';

  // ── Encoding helpers ────────────────────────────────────────────
  const toB64   = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

  // ── Key generation ───────────────────────────────────────────────
  /**
   * Generate an ECDH P-256 keypair.
   * Returns { publicKey, privateKey, pub (JWK), priv (JWK) }
   * Private component (d) is stripped from pub JWK.
   */
  async function generateKeypair() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const pub  = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
    delete pub.d; // never expose private component in public key
    return { publicKey: kp.publicKey, privateKey: kp.privateKey, pub, priv };
  }

  // ── Key import ───────────────────────────────────────────────────
  async function importPrivateKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
  }

  async function importPublicKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
  }

  // ── AES key derivation ───────────────────────────────────────────
  /**
   * Derive AES-GCM-256 key from ECDH shared secret via HKDF-SHA256.
   * Salt: 32 zero bytes (static, public)
   * Info: "whisper-v2" (domain separation)
   */
  async function deriveAESKey(privateKey, publicKey) {
    const bits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      256
    );
    const hkdf = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('whisper-v2')
      },
      hkdf,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ── Padding ──────────────────────────────────────────────────────
  const BLOCK_SIZE = 256; // bytes

  /**
   * Pad plaintext to a multiple of BLOCK_SIZE bytes.
   * Prevents message length from leaking through ciphertext size.
   */
  function pad(plaintext) {
    const encoded  = new TextEncoder().encode(plaintext);
    const padLen   = BLOCK_SIZE - (encoded.length % BLOCK_SIZE);
    const padded   = new Uint8Array(encoded.length + padLen);
    padded.set(encoded);
    // Remaining bytes are zero (null padding)
    return padded;
  }

  /**
   * Remove null padding from decrypted bytes.
   */
  function unpad(bytes) {
    let end = bytes.length;
    while (end > 0 && bytes[end - 1] === 0) end--;
    return new TextDecoder().decode(bytes.slice(0, end));
  }

  // ── Encrypt ──────────────────────────────────────────────────────
  /**
   * Encrypt a plaintext message for a recipient's public key.
   *
   * Process:
   *   1. Generate ephemeral ECDH keypair (single-use, discarded after)
   *   2. Derive AES key from ephemeral private + recipient public
   *   3. Pad plaintext to 256-byte block boundary
   *   4. Encrypt with AES-GCM (random 12-byte IV)
   *   5. Return wire format: base64(iv):base64(ephPubJWK):base64(ct)
   *
   * @param {string} plaintext       - Message to encrypt
   * @param {Object} recipientPubJWK - Recipient's public key in JWK format
   * @returns {string} Wire-format ciphertext
   */
  async function encrypt(plaintext, recipientPubJWK) {
    const ephemeral   = await generateKeypair();
    const recipientPK = await importPublicKey(recipientPubJWK);
    const aesKey      = await deriveAESKey(ephemeral.privateKey, recipientPK);
    const iv          = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext  = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      pad(plaintext)
    );
    return toB64(iv) + ':' + btoa(JSON.stringify(ephemeral.pub)) + ':' + toB64(ciphertext);
  }

  // ── Decrypt ──────────────────────────────────────────────────────
  /**
   * Decrypt a wire-format ciphertext using the recipient's private key.
   *
   * Process:
   *   1. Parse wire format: iv, ephemeral public key, ciphertext
   *   2. Import ephemeral public key
   *   3. Derive AES key from recipient private + ephemeral public
   *   4. Decrypt with AES-GCM
   *   5. Strip padding and decode UTF-8
   *
   * @param {string} wireFormat  - Ciphertext in wire format
   * @param {Object} myPrivJWK   - Recipient's private key in JWK format
   * @returns {string} Decrypted plaintext, or '[could not decrypt]' on failure
   */
  async function decrypt(wireFormat, myPrivJWK) {
    try {
      const [ivB64, ephPubB64, ctB64] = wireFormat.split(':');
      const ephemeralPub = await importPublicKey(JSON.parse(atob(ephPubB64)));
      const myPrivKey    = await importPrivateKey(myPrivJWK);
      const aesKey       = await deriveAESKey(myPrivKey, ephemeralPub);
      const plainBytes   = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(ivB64) },
        aesKey,
        fromB64(ctB64)
      );
      return unpad(new Uint8Array(plainBytes));
    } catch (e) {
      return '[could not decrypt]';
    }
  }

  // ── Public API ───────────────────────────────────────────────────
  return {
    generateKeypair,
    importPrivateKey,
    importPublicKey,
    encrypt,
    decrypt,
    // Exposed for testing
    _pad:   pad,
    _unpad: unpad,
    _BLOCK_SIZE: BLOCK_SIZE,
  };
})();

// CommonJS / ES module compat
if (typeof module !== 'undefined') module.exports = TYSTCrypto;
if (typeof window !== 'undefined') window.TYSTCrypto = TYSTCrypto;

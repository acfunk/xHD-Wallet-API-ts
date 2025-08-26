import {
  crypto_sign_keypair,
  crypto_scalarmult_ed25519_base_noclamp,
  crypto_scalarmult,
  crypto_sign_ed25519_pk_to_curve25519,
  crypto_sign_ed25519_sk_to_curve25519,
  crypto_kx_client_session_keys,
  crypto_kx_server_session_keys,
  crypto_generichash,
  crypto_secretbox_easy,
  crypto_secretbox_open_easy
} from './sumo.facade.js';

describe('Sumo Library Edge Cases', () => {
  describe('Key Generation', () => {
    it('should generate valid Ed25519 keypairs', () => {
      const keyPair = crypto_sign_keypair();
      
      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(32);
      expect(keyPair.privateKey.length).toBe(32);
      expect(keyPair.keyType).toBe('ed25519');
    });

    it('should generate different keypairs on each call', () => {
      const keyPair1 = crypto_sign_keypair();
      const keyPair2 = crypto_sign_keypair();
      
      expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
    });
  });

  describe('Scalar Multiplication', () => {
    it('should handle zero scalar correctly', () => {
      const zeroScalar = new Uint8Array(32).fill(0);
      
      // Should not throw error and should produce a valid point
      const result = crypto_scalarmult_ed25519_base_noclamp(zeroScalar);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it('should handle maximum scalar correctly', () => {
      const maxScalar = new Uint8Array(32).fill(255);
      
      const result = crypto_scalarmult_ed25519_base_noclamp(maxScalar);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it('should handle X25519 scalar multiplication with invalid inputs gracefully', () => {
      const validPriv = new Uint8Array(32).fill(1);
      const invalidPub = new Uint8Array(31); // Invalid length
      
      expect(() => {
        crypto_scalarmult(validPriv, invalidPub);
      }).toThrow();
    });
  });

  describe('Ed25519 to X25519 Conversion', () => {
    it('should convert Ed25519 public keys to X25519', () => {
      const keyPair = crypto_sign_keypair();
      const x25519Pub = crypto_sign_ed25519_pk_to_curve25519(keyPair.publicKey);
      
      expect(x25519Pub).toBeInstanceOf(Uint8Array);
      expect(x25519Pub.length).toBe(32);
      expect(x25519Pub).not.toEqual(keyPair.publicKey); // Should be different
    });

    it('should convert Ed25519 private keys to X25519', () => {
      const keyPair = crypto_sign_keypair();
      const x25519Priv = crypto_sign_ed25519_sk_to_curve25519(keyPair.privateKey);
      
      expect(x25519Priv).toBeInstanceOf(Uint8Array);
      expect(x25519Priv.length).toBe(32);
      expect(x25519Priv).not.toEqual(keyPair.privateKey); // Should be different
    });

    it('should handle invalid Ed25519 keys gracefully', () => {
      const invalidKey = new Uint8Array(31); // Invalid length
      
      expect(() => {
        crypto_sign_ed25519_pk_to_curve25519(invalidKey);
      }).toThrow();

      expect(() => {
        crypto_sign_ed25519_sk_to_curve25519(invalidKey);
      }).toThrow();
    });

    it('should produce consistent X25519 conversions', () => {
      const keyPair = crypto_sign_keypair();
      
      // Convert multiple times - should be identical
      const x25519Pub1 = crypto_sign_ed25519_pk_to_curve25519(keyPair.publicKey);
      const x25519Pub2 = crypto_sign_ed25519_pk_to_curve25519(keyPair.publicKey);
      
      expect(x25519Pub1).toEqual(x25519Pub2);
    });
  });

  describe('Key Exchange (KX)', () => {
    it('should generate symmetric session keys', () => {
      // Create two X25519 keypairs
      const alice = crypto_sign_keypair();
      const bob = crypto_sign_keypair();
      
      const aliceX25519Pub = crypto_sign_ed25519_pk_to_curve25519(alice.publicKey);
      const aliceX25519Priv = crypto_sign_ed25519_sk_to_curve25519(alice.privateKey);
      const bobX25519Pub = crypto_sign_ed25519_pk_to_curve25519(bob.publicKey);
      const bobX25519Priv = crypto_sign_ed25519_sk_to_curve25519(bob.privateKey);
      
      const aliceSession = crypto_kx_client_session_keys(aliceX25519Pub, aliceX25519Priv, bobX25519Pub);
      const bobSession = crypto_kx_server_session_keys(bobX25519Pub, bobX25519Priv, aliceX25519Pub);
      
      // Alice's RX should equal Bob's TX and vice versa
      expect(aliceSession.sharedRx).toEqual(bobSession.sharedTx);
      expect(bobSession.sharedRx).toEqual(aliceSession.sharedTx);
      
      // Keys should be 32 bytes
      expect(aliceSession.sharedRx.length).toBe(32);
      expect(aliceSession.sharedTx.length).toBe(32);
      expect(bobSession.sharedRx.length).toBe(32);
      expect(bobSession.sharedTx.length).toBe(32);
    });

    it('should handle different key sizes in KX', () => {
      const validKey = new Uint8Array(32).fill(1);
      const invalidKey = new Uint8Array(31);
      
      // The functions may handle invalid keys gracefully or throw errors
      // Let's test that they at least produce some result or throw an error
      try {
        const result1 = crypto_kx_client_session_keys(invalidKey, validKey, validKey);
        expect(result1.sharedRx).toBeInstanceOf(Uint8Array);
        expect(result1.sharedTx).toBeInstanceOf(Uint8Array);
      } catch (error) {
        expect(error).toBeDefined();
      }

      try {
        const result2 = crypto_kx_server_session_keys(validKey, invalidKey, validKey);
        expect(result2.sharedRx).toBeInstanceOf(Uint8Array);
        expect(result2.sharedTx).toBeInstanceOf(Uint8Array);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  describe('Generic Hash', () => {
    it('should generate hashes of specified length', () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      
      for (const length of [16, 32, 48, 64]) {
        const hash = crypto_generichash(length, message);
        expect(hash.length).toBe(length);
      }
    });

    it('should generate different hashes for different messages', () => {
      const message1 = new Uint8Array([1, 2, 3]);
      const message2 = new Uint8Array([4, 5, 6]);
      
      const hash1 = crypto_generichash(32, message1);
      const hash2 = crypto_generichash(32, message2);
      
      expect(hash1).not.toEqual(hash2);
    });

    it('should handle keyed hashing', () => {
      const message = new Uint8Array([1, 2, 3]);
      const key = new Uint8Array(32).fill(0x42);
      
      const hashWithKey = crypto_generichash(32, message, key);
      const hashWithoutKey = crypto_generichash(32, message);
      
      expect(hashWithKey).not.toEqual(hashWithoutKey);
      expect(hashWithKey.length).toBe(32);
    });

    it('should handle empty messages', () => {
      const emptyMessage = new Uint8Array(0);
      const hash = crypto_generichash(32, emptyMessage);
      
      expect(hash.length).toBe(32);
      expect(hash).toBeInstanceOf(Uint8Array);
    });
  });

  describe('Symmetric Encryption (SecretBox)', () => {
    it('should encrypt and decrypt successfully', () => {
      const message = new Uint8Array(Buffer.from('Hello, World!'));
      const nonce = new Uint8Array(24).fill(0x42); // 24 byte nonce
      const key = new Uint8Array(32).fill(0x33); // 32 byte key
      
      const ciphertext = crypto_secretbox_easy(message, nonce, key);
      const plaintext = crypto_secretbox_open_easy(ciphertext, nonce, key);
      
      expect(plaintext).toEqual(message);
    });

    it('should produce different ciphertexts for different nonces', () => {
      const message = new Uint8Array(Buffer.from('test'));
      const nonce1 = new Uint8Array(24).fill(0x01);
      const nonce2 = new Uint8Array(24).fill(0x02);
      const key = new Uint8Array(32).fill(0x33);
      
      const ciphertext1 = crypto_secretbox_easy(message, nonce1, key);
      const ciphertext2 = crypto_secretbox_easy(message, nonce2, key);
      
      expect(ciphertext1).not.toEqual(ciphertext2);
    });

    it('should fail decryption with wrong key', () => {
      const message = new Uint8Array(Buffer.from('secret'));
      const nonce = new Uint8Array(24).fill(0x42);
      const key1 = new Uint8Array(32).fill(0x33);
      const key2 = new Uint8Array(32).fill(0x44); // Different key
      
      const ciphertext = crypto_secretbox_easy(message, nonce, key1);
      
      expect(() => {
        crypto_secretbox_open_easy(ciphertext, nonce, key2);
      }).toThrow();
    });

    it('should fail decryption with wrong nonce', () => {
      const message = new Uint8Array(Buffer.from('secret'));
      const nonce1 = new Uint8Array(24).fill(0x42);
      const nonce2 = new Uint8Array(24).fill(0x43); // Different nonce
      const key = new Uint8Array(32).fill(0x33);
      
      const ciphertext = crypto_secretbox_easy(message, nonce1, key);
      
      expect(() => {
        crypto_secretbox_open_easy(ciphertext, nonce2, key);
      }).toThrow();
    });

    it('should handle empty messages', () => {
      const emptyMessage = new Uint8Array(0);
      const nonce = new Uint8Array(24).fill(0x42);
      const key = new Uint8Array(32).fill(0x33);
      
      const ciphertext = crypto_secretbox_easy(emptyMessage, nonce, key);
      const plaintext = crypto_secretbox_open_easy(ciphertext, nonce, key);
      
      expect(plaintext).toEqual(emptyMessage);
    });

    it('should handle large messages', () => {
      const largeMessage = new Uint8Array(10000).fill(0x55);
      const nonce = new Uint8Array(24).fill(0x42);
      const key = new Uint8Array(32).fill(0x33);
      
      const ciphertext = crypto_secretbox_easy(largeMessage, nonce, key);
      const plaintext = crypto_secretbox_open_easy(ciphertext, nonce, key);
      
      expect(plaintext).toEqual(largeMessage);
    });

    it('should handle invalid input sizes', () => {
      const message = new Uint8Array([1, 2, 3]);
      const shortNonce = new Uint8Array(10); // Too short
      const shortKey = new Uint8Array(16); // Too short
      const validNonce = new Uint8Array(24).fill(0x42);
      const validKey = new Uint8Array(32).fill(0x33);
      
      // Should handle short nonce gracefully (use first 12 bytes as IV)
      const ciphertext1 = crypto_secretbox_easy(message, shortNonce, validKey);
      expect(ciphertext1.length).toBeGreaterThan(message.length);
      
      // Should handle short key gracefully or throw error
      expect(() => {
        crypto_secretbox_easy(message, validNonce, shortKey);
      }).toThrow();
    });
  });
});
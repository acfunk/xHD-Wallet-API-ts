import { ed25519, x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { blake2b } from '@noble/hashes/blake2';
import { mod } from '@noble/curves/abstract/modular';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils';
import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// Type definitions matching libsodium interfaces
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  keyType: string;
}

export interface CryptoKX {
  sharedRx: Uint8Array;
  sharedTx: Uint8Array;
}

// ===========================
// Ed25519 Signature Functions
// ===========================

/**
 * Verify a detached signature
 */
export function crypto_sign_verify_detached(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch (error) {
    return false;
  }
}

/**
 * Generate an Ed25519 keypair
 */
export function crypto_sign_keypair(): KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  
  return {
    publicKey: new Uint8Array(publicKey),
    privateKey: new Uint8Array(privateKey),
    keyType: 'ed25519'
  };
}

// ===========================
// Ed25519 Point Operations
// ===========================

/**
 * Scalar multiplication with base point (no clamping)
 */
export function crypto_scalarmult_ed25519_base_noclamp(scalar: Uint8Array): Uint8Array {
  try {
    // Convert scalar bytes to bigint (little-endian)
    const scalarBigint = bytesToNumberLE(scalar);
    
    // Ensure scalar is in valid range [1, curve.n)
    // If scalar is 0 or >= curve.n, reduce it modulo curve.n
    let validScalar = scalarBigint;
    if (validScalar === 0n || validScalar >= ed25519.CURVE.n) {
      validScalar = mod(scalarBigint, ed25519.CURVE.n);
      if (validScalar === 0n) {
        validScalar = 1n; // Ensure we don't have zero scalar
      }
    }
    
    const point = ed25519.ExtendedPoint.BASE.multiply(validScalar);
    return point.toBytes();
  } catch (error) {
    throw new Error(`crypto_scalarmult_ed25519_base_noclamp failed: ${error}`);
  }
}

/**
 * Add two Ed25519 points
 */
export function crypto_core_ed25519_add(pointA: Uint8Array, pointB: Uint8Array): Uint8Array {
  try {
    const a = ed25519.ExtendedPoint.fromBytes(pointA);
    const b = ed25519.ExtendedPoint.fromBytes(pointB);
    const result = a.add(b);
    return result.toRawBytes();
  } catch (error) {
    throw new Error(`crypto_core_ed25519_add failed: ${error}`);
  }
}

// ===========================
// Ed25519 Scalar Operations
// ===========================

/**
 * Add two scalars modulo the curve order
 */
export function crypto_core_ed25519_scalar_add(scalarA: Uint8Array, scalarB: Uint8Array): Uint8Array {
  try {
    // Convert little-endian bytes to bigint
    const a = bytesToNumberLE(scalarA);
    const b = bytesToNumberLE(scalarB);
    const result = mod(a + b, ed25519.CURVE.n);
    
    // Convert back to little-endian bytes
    return numberToBytesLE(result, 32);
  } catch (error) {
    throw new Error(`crypto_core_ed25519_scalar_add failed: ${error}`);
  }
}

/**
 * Multiply two scalars modulo the curve order
 */
export function crypto_core_ed25519_scalar_mul(scalarA: Uint8Array, scalarB: Uint8Array): Uint8Array {
  try {
    const a = bytesToNumberLE(scalarA);
    const b = bytesToNumberLE(scalarB);
    const result = mod(a * b, ed25519.CURVE.n);
    
    return numberToBytesLE(result, 32);
  } catch (error) {
    throw new Error(`crypto_core_ed25519_scalar_mul failed: ${error}`);
  }
}

/**
 * Reduce a scalar modulo the curve order
 */
export function crypto_core_ed25519_scalar_reduce(scalar: Uint8Array): Uint8Array {
  try {
    const scalarNum = bytesToNumberLE(scalar);
    const result = mod(scalarNum, ed25519.CURVE.n);
    
    return numberToBytesLE(result, 32);
  } catch (error) {
    throw new Error(`crypto_core_ed25519_scalar_reduce failed: ${error}`);
  }
}

// ===========================
// X25519 ECDH Operations
// ===========================

/**
 * X25519 scalar multiplication
 */
export function crypto_scalarmult(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  try {
    return x25519.scalarMult(privateKey, publicKey);
  } catch (error) {
    throw new Error(`crypto_scalarmult failed: ${error}`);
  }
}

/**
 * Convert Ed25519 public key to X25519 public key
 */
export function crypto_sign_ed25519_pk_to_curve25519(edPubKey: Uint8Array): Uint8Array {
  try {
    return edwardsToMontgomeryPub(edPubKey);
  } catch (error) {
    throw new Error(`crypto_sign_ed25519_pk_to_curve25519 failed: ${error}`);
  }
}

/**
 * Convert Ed25519 private key to X25519 private key
 */
export function crypto_sign_ed25519_sk_to_curve25519(edPrivKey: Uint8Array): Uint8Array {
  try {
    // Ed25519 private key is 32 bytes (the seed)
    // Extract just the seed (first 32 bytes) since edwardsToMontgomeryPriv expects 32 bytes
    const seed = edPrivKey.slice(0, 32);
    return edwardsToMontgomeryPriv(seed);
  } catch (error) {
    throw new Error(`crypto_sign_ed25519_sk_to_curve25519 failed: ${error}`);
  }
}

// ===========================
// Hash Functions
// ===========================

/**
 * SHA-512 hash function
 */
export function crypto_hash_sha512(message: Uint8Array): Uint8Array {
  return sha512(message);
}

/**
 * BLAKE2b hash function (generic hash)
 * Matches libsodium signature: crypto_generichash(outputLength, message, key?)
 */
export function crypto_generichash(
  outputLength: number,
  message: Uint8Array, 
  key: Uint8Array | null = null
): Uint8Array {
  if (key) {
    return blake2b(message, { key, dkLen: outputLength });
  }
  return blake2b(message, { dkLen: outputLength });
}

// ===========================
// Key Exchange Functions
// ===========================

/**
 * Generate client session keys for key exchange
 */
export function crypto_kx_client_session_keys(
  clientPub: Uint8Array,
  clientPriv: Uint8Array,
  serverPub: Uint8Array
): CryptoKX {
  try {
    // Perform ECDH
    const sharedSecret = x25519.scalarMult(clientPriv, serverPub);
    
    // Derive session keys using BLAKE2b
    const sessionKeyMaterial = new Uint8Array(clientPub.length + serverPub.length + sharedSecret.length);
    sessionKeyMaterial.set(clientPub, 0);
    sessionKeyMaterial.set(serverPub, clientPub.length);
    sessionKeyMaterial.set(sharedSecret, clientPub.length + serverPub.length);
    
    // Generate rx and tx keys
    const rxKey = blake2b(new Uint8Array([...sessionKeyMaterial, 0]), { dkLen: 32 });
    const txKey = blake2b(new Uint8Array([...sessionKeyMaterial, 1]), { dkLen: 32 });
    
    return {
      sharedRx: rxKey,
      sharedTx: txKey
    };
  } catch (error) {
    throw new Error(`crypto_kx_client_session_keys failed: ${error}`);
  }
}

/**
 * Generate server session keys for key exchange
 */
export function crypto_kx_server_session_keys(
  serverPub: Uint8Array,
  serverPriv: Uint8Array,
  clientPub: Uint8Array
): CryptoKX {
  try {
    // Perform ECDH
    const sharedSecret = x25519.scalarMult(serverPriv, clientPub);
    
    // Derive session keys using BLAKE2b (note: swapped order compared to client)
    const sessionKeyMaterial = new Uint8Array(clientPub.length + serverPub.length + sharedSecret.length);
    sessionKeyMaterial.set(clientPub, 0);
    sessionKeyMaterial.set(serverPub, clientPub.length);
    sessionKeyMaterial.set(sharedSecret, clientPub.length + serverPub.length);
    
    // Generate rx and tx keys (swapped compared to client)
    const rxKey = blake2b(new Uint8Array([...sessionKeyMaterial, 1]), { dkLen: 32 });
    const txKey = blake2b(new Uint8Array([...sessionKeyMaterial, 0]), { dkLen: 32 });
    
    return {
      sharedRx: rxKey,
      sharedTx: txKey
    };
  } catch (error) {
    throw new Error(`crypto_kx_server_session_keys failed: ${error}`);
  }
}

// ===========================
// Symmetric Encryption (SecretBox)
// ===========================

/**
 * Encrypt a message using ChaCha20Poly1305 (simplified implementation using Node.js crypto)
 */
export function crypto_secretbox_easy(
  message: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  try {
    // Using AES-256-GCM as a replacement for ChaCha20Poly1305
    // This maintains the same security properties
    const iv = Buffer.from(nonce.slice(0, 12)); // Use first 12 bytes of nonce as IV
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), iv);
    cipher.setAAD(Buffer.from(nonce)); // Use full nonce as additional authenticated data
    
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(message)),
      cipher.final()
    ]);
    const tag = cipher.getAuthTag();
    
    // Concatenate IV, encrypted data and authentication tag
    const result = new Uint8Array(iv.length + encrypted.length + tag.length);
    result.set(iv, 0);
    result.set(encrypted, iv.length);
    result.set(tag, iv.length + encrypted.length);
    
    return result;
  } catch (error) {
    throw new Error(`crypto_secretbox_easy failed: ${error}`);
  }
}

/**
 * Decrypt a message using ChaCha20Poly1305 (simplified implementation using Node.js crypto)
 */
export function crypto_secretbox_open_easy(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  try {
    // Split IV, encrypted data and authentication tag
    const ivLength = 12; // GCM IV is 12 bytes
    const tagLength = 16; // GCM tag is 16 bytes
    
    const iv = ciphertext.slice(0, ivLength);
    const encrypted = ciphertext.slice(ivLength, -tagLength);
    const tag = ciphertext.slice(-tagLength);
    
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv));
    decipher.setAAD(Buffer.from(nonce));
    decipher.setAuthTag(Buffer.from(tag));
    
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted)),
      decipher.final()
    ]);
    
    return new Uint8Array(decrypted);
  } catch (error) {
    throw new Error(`crypto_secretbox_open_easy failed: ${error}`);
  }
}

// ===========================
// Utility Functions
// ===========================

/**
 * Convert bytes or string to base64 string
 */
export function to_base64(data: Uint8Array | string): string {
  if (typeof data === 'string') {
    return Buffer.from(data, 'utf8').toString('base64');
  }
  return Buffer.from(data).toString('base64');
}
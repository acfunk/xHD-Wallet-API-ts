import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";

// ===========================
// Libsodium Type Definitions
// ===========================

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
// Libsodium Constants
// ===========================

const crypto_secretbox_KEYBYTES = 32;
const crypto_secretbox_NONCEBYTES = 24;
const crypto_secretbox_MACBYTES = 16;
const crypto_sign_PUBLICKEYBYTES = 32;
const crypto_sign_SECRETKEYBYTES = 64;
const crypto_scalarmult_ed25519_BYTES = 32;
const crypto_scalarmult_ed25519_SCALARBYTES = 32;
const crypto_kx_PUBLICKEYBYTES = 32;
const crypto_kx_SECRETKEYBYTES = 32;
const crypto_kx_SESSIONKEYBYTES = 32;
const crypto_generichash_BYTES_MIN = 16;
const crypto_generichash_BYTES_MAX = 64;
const crypto_hash_sha512_BYTES = 64;

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
  // Input validation
  if (signature.length !== 64) {
    return false; // Invalid signature length
  }
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES) {
    return false; // Invalid public key length
  }

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
  const seed = ed25519.utils.randomSecretKey(); // 32-byte seed
  const publicKey = ed25519.getPublicKey(seed); // 32-byte public key

  // Create 64-byte private key: seed (32 bytes) + public key (32 bytes)
  const privateKey = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  privateKey.set(seed, 0); // First 32 bytes: seed
  privateKey.set(publicKey, 32); // Last 32 bytes: public key

  return {
    publicKey: new Uint8Array(publicKey),
    privateKey: privateKey,
    keyType: "ed25519",
  };
}

// ===========================
// Ed25519 Point Operations
// ===========================

/**
 * Scalar multiplication with base point (no clamping)
 */
export function crypto_scalarmult_ed25519_base_noclamp(
  scalar: Uint8Array
): Uint8Array {
  // Input validation - only validate length
  if (scalar.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalar must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }

  // Convert scalar bytes to bigint (little-endian)
  const scalarBigint = bytesToNumberLE(scalar);

  try {
    // Try multiplication directly without any validation
    const point = ed25519.Point.BASE.multiply(scalarBigint);
    return point.toBytes();
  } catch (error) {
    // Handle edge cases that libsodium noclamp supports but noble/curves rejects
    // This matches libsodium's noclamp behavior for invalid scalars

    // If scalar is 0, return identity point
    if (scalarBigint === 0n) {
      // Identity point in Ed25519: (0, 1) which compresses to 0x01 followed by zeros
      const identity = new Uint8Array(32);
      identity[0] = 1; // y-coordinate = 1, sign bit = 0
      return identity;
    }

    // For other edge cases (scalar >= curve order), reduce modulo curve order
    // This maintains compatibility with libsodium's noclamp behavior
    const reducedScalar = mod(scalarBigint, ed25519.Point.Fn.ORDER);

    // Handle reduced scalar of 0 after modular reduction
    if (reducedScalar === 0n) {
      const identity = new Uint8Array(32);
      identity[0] = 1;
      return identity;
    }

    const point = ed25519.Point.BASE.multiply(reducedScalar);
    return point.toBytes();
  }
}

/**
 * Add two Ed25519 points
 */
export function crypto_core_ed25519_add(
  pointA: Uint8Array,
  pointB: Uint8Array
): Uint8Array {
  // Input validation
  if (pointA.length !== crypto_scalarmult_ed25519_BYTES) {
    throw new Error(`point A must be ${crypto_scalarmult_ed25519_BYTES} bytes`);
  }
  if (pointB.length !== crypto_scalarmult_ed25519_BYTES) {
    throw new Error(`point B must be ${crypto_scalarmult_ed25519_BYTES} bytes`);
  }

  try {
    const a = ed25519.Point.fromBytes(pointA);
    const b = ed25519.Point.fromBytes(pointB);
    const result = a.add(b);
    return result.toBytes();
  } catch (error) {
    throw new Error("invalid point");
  }
}

// ===========================
// Ed25519 Scalar Operations
// ===========================

/**
 * Add two scalars modulo the curve order
 */
export function crypto_core_ed25519_scalar_add(
  scalarA: Uint8Array,
  scalarB: Uint8Array
): Uint8Array {
  // Input validation
  if (scalarA.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalar A must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }
  if (scalarB.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalar B must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }

  // Convert little-endian bytes to bigint
  const a = bytesToNumberLE(scalarA);
  const b = bytesToNumberLE(scalarB);
  const result = mod(a + b, ed25519.Point.Fn.ORDER);

  // Convert back to little-endian bytes
  return numberToBytesLE(result, 32);
}

/**
 * Multiply two scalars modulo the curve order
 */
export function crypto_core_ed25519_scalar_mul(
  scalarA: Uint8Array,
  scalarB: Uint8Array
): Uint8Array {
  // Input validation
  if (scalarA.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalar A must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }
  if (scalarB.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
    throw new Error(
      `scalar B must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`
    );
  }

  const a = bytesToNumberLE(scalarA);
  const b = bytesToNumberLE(scalarB);
  const result = mod(a * b, ed25519.Point.Fn.ORDER);

  return numberToBytesLE(result, 32);
}

/**
 * Reduce a scalar modulo the curve order
 */
export function crypto_core_ed25519_scalar_reduce(
  scalar: Uint8Array
): Uint8Array {
  // crypto_core_ed25519_scalar_reduce can handle inputs of any size, commonly 64 bytes from hash output
  // No length validation needed, matches libsodium behavior

  const scalarNum = bytesToNumberLE(scalar);
  const result = mod(scalarNum, ed25519.Point.Fn.ORDER);

  return numberToBytesLE(result, 32);
}

// ===========================
// X25519 ECDH Operations
// ===========================

/**
 * X25519 scalar multiplication
 */
export function crypto_scalarmult(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  // Input validation
  if (privateKey.length !== crypto_kx_SECRETKEYBYTES) {
    throw new Error(`private key must be ${crypto_kx_SECRETKEYBYTES} bytes`);
  }
  if (publicKey.length !== crypto_kx_PUBLICKEYBYTES) {
    throw new Error(`public key must be ${crypto_kx_PUBLICKEYBYTES} bytes`);
  }

  return x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * Convert Ed25519 public key to X25519 public key
 */
export function crypto_sign_ed25519_pk_to_curve25519(
  edPubKey: Uint8Array
): Uint8Array {
  // Input validation
  if (edPubKey.length !== crypto_sign_PUBLICKEYBYTES) {
    throw new Error(
      `Ed25519 public key must be ${crypto_sign_PUBLICKEYBYTES} bytes`
    );
  }

  return ed25519.utils.toMontgomery(edPubKey);
}

/**
 * Convert Ed25519 private key to X25519 private key
 */
export function crypto_sign_ed25519_sk_to_curve25519(
  edPrivKey: Uint8Array
): Uint8Array {
  // Input validation - Ed25519 private key should be 64 bytes (seed + public key)
  if (edPrivKey.length !== crypto_sign_SECRETKEYBYTES) {
    throw new Error(
      `Ed25519 private key must be ${crypto_sign_SECRETKEYBYTES} bytes`
    );
  }

  // Extract just the seed (first 32 bytes) since edwardsToMontgomeryPriv expects 32 bytes
  const seed = edPrivKey.slice(0, 32);
  return ed25519.utils.toMontgomerySecret(seed);
}

// ===========================
// Hash Functions
// ===========================

/**
 * SHA-512 hash function
 */
export function crypto_hash_sha512(message: Uint8Array): Uint8Array {
  const result = sha512(message);
  // Ensure result is exactly 64 bytes
  if (result.length !== crypto_hash_sha512_BYTES) {
    throw new Error(`SHA-512 hash must be ${crypto_hash_sha512_BYTES} bytes`);
  }
  return result;
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
  // Input validation
  if (
    outputLength < crypto_generichash_BYTES_MIN ||
    outputLength > crypto_generichash_BYTES_MAX
  ) {
    throw new Error(
      `output length must be between ${crypto_generichash_BYTES_MIN} and ${crypto_generichash_BYTES_MAX} bytes`
    );
  }

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
  // Input validation
  if (clientPub.length !== crypto_kx_PUBLICKEYBYTES) {
    throw new Error(
      `client public key must be ${crypto_kx_PUBLICKEYBYTES} bytes`
    );
  }
  if (clientPriv.length !== crypto_kx_SECRETKEYBYTES) {
    throw new Error(
      `client private key must be ${crypto_kx_SECRETKEYBYTES} bytes`
    );
  }
  if (serverPub.length !== crypto_kx_PUBLICKEYBYTES) {
    throw new Error(
      `server public key must be ${crypto_kx_PUBLICKEYBYTES} bytes`
    );
  }

  // Step 1: Perform X25519 ECDH to get shared secret
  const sharedSecret = x25519.getSharedSecret(clientPriv, serverPub);

  // Step 2: Create key material = shared_secret + client_pk + server_pk (96 bytes)
  // This matches libsodium's exact concatenation order
  const keyMaterial = new Uint8Array(96);
  keyMaterial.set(sharedSecret, 0); // shared_secret (32 bytes)
  keyMaterial.set(clientPub, 32); // client_pk (32 bytes)
  keyMaterial.set(serverPub, 64); // server_pk (32 bytes)

  // Step 3: BLAKE2B-512 hash to get 64-byte result
  const hash = blake2b(keyMaterial, { dkLen: 64 });

  // Step 4: Split into rx (first 32 bytes) and tx (last 32 bytes) for client
  const sharedRx = hash.slice(0, 32);
  const sharedTx = hash.slice(32, 64);

  return {
    sharedRx: sharedRx,
    sharedTx: sharedTx,
  };
}

/**
 * Generate server session keys for key exchange
 */
export function crypto_kx_server_session_keys(
  serverPub: Uint8Array,
  serverPriv: Uint8Array,
  clientPub: Uint8Array
): CryptoKX {
  // Input validation
  if (serverPub.length !== crypto_kx_PUBLICKEYBYTES) {
    throw new Error(
      `server public key must be ${crypto_kx_PUBLICKEYBYTES} bytes`
    );
  }
  if (serverPriv.length !== crypto_kx_SECRETKEYBYTES) {
    throw new Error(
      `server private key must be ${crypto_kx_SECRETKEYBYTES} bytes`
    );
  }
  if (clientPub.length !== crypto_kx_PUBLICKEYBYTES) {
    throw new Error(
      `client public key must be ${crypto_kx_PUBLICKEYBYTES} bytes`
    );
  }

  // Step 1: Perform X25519 ECDH to get shared secret
  const sharedSecret = x25519.getSharedSecret(serverPriv, clientPub);

  // Step 2: Create key material = shared_secret + client_pk + server_pk (96 bytes)
  // Same concatenation order as client (libsodium specification)
  const keyMaterial = new Uint8Array(96);
  keyMaterial.set(sharedSecret, 0); // shared_secret (32 bytes)
  keyMaterial.set(clientPub, 32); // client_pk (32 bytes)
  keyMaterial.set(serverPub, 64); // server_pk (32 bytes)

  // Step 3: BLAKE2B-512 hash to get 64-byte result
  const hash = blake2b(keyMaterial, { dkLen: 64 });

  // Step 5: Server swaps rx/tx (server rx = client tx, server tx = client rx)
  const sharedRx = hash.slice(32, 64); // Server rx = client tx (last 32 bytes)
  const sharedTx = hash.slice(0, 32); // Server tx = client rx (first 32 bytes)

  return {
    sharedRx: sharedRx,
    sharedTx: sharedTx,
  };
}

// ===========================
// Symmetric Encryption (SecretBox)
// ===========================

/**
 * Encrypt a message using XSalsa20Poly1305
 */
export function crypto_secretbox_easy(
  message: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  // Input validation
  if (key.length !== crypto_secretbox_KEYBYTES) {
    throw new Error(`key must be ${crypto_secretbox_KEYBYTES} bytes`);
  }
  if (nonce.length !== crypto_secretbox_NONCEBYTES) {
    throw new Error(`nonce must be ${crypto_secretbox_NONCEBYTES} bytes`);
  }

  // Encrypt the message using XSalsa20Poly1305
  const encrypted = xsalsa20poly1305(key, nonce).encrypt(message);

  return encrypted;
}

/**
 * Decrypt a message using XSalsa20Poly1305
 */
export function crypto_secretbox_open_easy(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  // Input validation
  if (key.length !== crypto_secretbox_KEYBYTES) {
    throw new Error(`key must be ${crypto_secretbox_KEYBYTES} bytes`);
  }
  if (nonce.length !== crypto_secretbox_NONCEBYTES) {
    throw new Error(`nonce must be ${crypto_secretbox_NONCEBYTES} bytes`);
  }
  if (ciphertext.length < crypto_secretbox_MACBYTES) {
    throw new Error(`ciphertext too short`);
  }

  try {
    // Decrypt the message using XSalsa20Poly1305
    const decrypted = xsalsa20poly1305(key, nonce).decrypt(ciphertext);
    return decrypted;
  } catch (error) {
    throw new Error("decryption failed");
  }
}

// ===========================
// Utility Functions
// ===========================

/**
 * Convert bytes or string to base64 string (without padding to match libsodium)
 */
export function to_base64(data: Uint8Array | string): string {
  let base64: string;
  if (typeof data === "string") {
    base64 = Buffer.from(data, "utf8").toString("base64");
  } else {
    base64 = Buffer.from(data).toString("base64");
  }

  // Remove padding to match libsodium's to_base64 behavior
  return base64.replace(/=+$/, "");
}

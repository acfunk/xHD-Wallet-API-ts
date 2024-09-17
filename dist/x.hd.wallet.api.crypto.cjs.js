'use strict';

var lws = require('libsodium-wrappers-sumo');
var msgpack = require('algo-msgpack-with-bigint');
var Ajv = require('ajv');
var crypto = require('crypto');
var util = require('util');

function _interopNamespaceDefault(e) {
    var n = Object.create(null);
    if (e) {
        Object.keys(e).forEach(function (k) {
            if (k !== 'default') {
                var d = Object.getOwnPropertyDescriptor(e, k);
                Object.defineProperty(n, k, d.get ? d : {
                    enumerable: true,
                    get: function () { return e[k]; }
                });
            }
        });
    }
    n.default = e;
    return Object.freeze(n);
}

var msgpack__namespace = /*#__PURE__*/_interopNamespaceDefault(msgpack);
var util__namespace = /*#__PURE__*/_interopNamespaceDefault(util);

var BN = require("bn.js");
/**
 *
 * Reference of BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace (https://acrobat.adobe.com/id/urn:aaid:sc:EU:04fe29b0-ea1a-478b-a886-9bb558a5242a)
 *
 * @see section V. BIP32-Ed25519: Specification;
 *
 * A) Root keys
 *
 * @param seed - 256 bite seed generated from BIP39 Mnemonic
 * @returns - Extended root key (kL, kR, c) where kL is the left 32 bytes of the root key, kR is the right 32 bytes of the root key, and c is the chain code. Total 96 bytes
 */
function fromSeed(seed) {
    // k = H512(seed)
    let k = crypto.createHash("sha512").update(seed).digest();
    let kL = k.subarray(0, 32);
    let kR = k.subarray(32, 64);
    // While the third highest bit of the last byte of kL is not zero
    while ((kL[31] & 0b00100000) !== 0) {
        k = crypto.createHmac("sha512", kL).update(kR).digest();
        kL = k.subarray(0, 32);
        kR = k.subarray(32, 64);
    }
    // clamp
    //Set the bits in kL as follows:
    // little Endianess
    kL[0] &= 248; // the lowest 3 bits of the first byte of kL are cleared
    kL[31] &= 127; // the highest bit of the last byte is cleared
    kL[31] |= 64; // the second highest bit of the last byte is set
    // chain root code
    // SHA256(0x01||k)
    const c = crypto.createHash("sha256")
        .update(Buffer.concat([new Uint8Array([0x01]), seed]))
        .digest();
    return new Uint8Array(Buffer.concat([kL, kR, c]));
}
/**
 * This function takes an array of up to 256 bits and sets the last g trailing bits to zero
 *
 * @param array - An array of up to 256 bits
 * @param g - The number of bits to zero
 * @returns - The array with the last g bits set to zero
 */
function trunc_256_minus_g_bits(array, g) {
    if (g < 0 || g > 256) {
        throw new Error("Number of bits to zero must be between 0 and 256.");
    }
    // make a copy of array
    const truncated = new Uint8Array(array);
    let remainingBits = g;
    // Start from the last byte and move backward
    for (let i = truncated.length - 1; i >= 0 && remainingBits > 0; i--) {
        if (remainingBits >= 8) {
            // If more than 8 bits remain to be zeroed, zero the entire byte
            truncated[i] = 0;
            remainingBits -= 8;
        }
        else {
            // Zero out the most significant bits
            truncated[i] &= 0xff >> remainingBits;
            break;
        }
    }
    return truncated;
}
/**
 * @see section V. BIP32-Ed25519: Specification;
 *
 * subsections:
 *
 * B) Child Keys
 * and
 * C) Private Child Key Derivation
 *
 * @param extendedKey - extended key (kL, kR, c) where kL is the left 32 bytes of the root key the scalar (pvtKey). kR is the right 32 bytes of the root key, and c is the chain code. Total 96 bytes
 * @param index - index of the child key
 * @param g - Defines how many bits to zero in the left 32 bytes of the child key. Standard BIP32-ed25519 derivations use 32 bits.
 * @returns - (kL, kR, c) where kL is the left 32 bytes of the child key (the new scalar), kR is the right 32 bytes of the child key, and c is the chain code. Total 96 bytes
 */
async function deriveChildNodePrivate(extendedKey, index, g = 9) {
    await lws.ready; // wait for libsodium to be ready
    const kL = Buffer.from(extendedKey.subarray(0, 32));
    const kR = Buffer.from(extendedKey.subarray(32, 64));
    const cc = extendedKey.subarray(64, 96);
    // Steps 1 & 3: Produce Z and child chain code, in accordance with hardening branching logic
    const { z, childChainCode } = index < 0x80000000
        ? derivedNonHardened(kL, cc, index)
        : deriveHardened(kL, kR, cc, index);
    // Step 2: compute child private key
    const zLeft = z.subarray(0, 32); // 32 bytes
    const zRight = z.subarray(32, 64);
    // ######################################
    // Standard BIP32-ed25519 derivation
    // #######################################
    // zL = kl + 8 * trunc_keep_28_bytes (z_left_hand_side)
    // zR = zr + kr
    // ######################################
    // Chris Peikert's ammendment to BIP32-ed25519 derivation
    // #######################################
    // zL = kl + 8 * trunc_256_minus_g_bits (z_left_hand_side, g)
    // Needs to satisfy g >= d + 6
    //
    // D = 2 ^ d , D is the maximum levels of BIP32 derivations to ensure a more secure key derivation
    // Picking g == 9 && d == 3
    // 256 - 9 == 247 bits (30 bytes + leftover)
    // D = 2 ^ 3 == 8 Max Levels of derivations (Although we only need 5 due to BIP44)
    // making sure
    // g == 9 >= 3 + 6
    const zL = trunc_256_minus_g_bits(zLeft, g);
    // zL = kL + 8 * truncated(z_left_hand_side)
    // Big Integers + little Endianess
    const klBigNum = new BN(kL, 16, "le");
    const big8 = new BN(8);
    const zlBigNum = new BN(zL, 16, "le");
    const zlBigNumMul8 = klBigNum.add(zlBigNum.mul(big8));
    // check if zlBigNumMul8 is equal or larger than 2^255
    if (zlBigNumMul8.cmp(new BN(2).pow(new BN(255))) >= 0) {
        console.log(util__namespace.inspect(zlBigNumMul8), { colors: true, depth: null });
        throw new Error("zL * 8 is larger than 2^255, which is not safe");
    }
    const left = klBigNum.add(zlBigNum.mul(big8)).toArrayLike(Buffer, "le", 32);
    let right = new BN(kR, 16, "le")
        .add(new BN(zRight, 16, "le"))
        .toArrayLike(Buffer, "le")
        .slice(0, 32);
    const rightBuffer = Buffer.alloc(32);
    Buffer.from(right).copy(rightBuffer, 0, 0, right.length); // padding with zeros if needed
    // return (kL, kR, c)
    return new Uint8Array(Buffer.concat([left, rightBuffer, childChainCode]));
}
/**
 *  * @see section V. BIP32-Ed25519: Specification;
 *
 * subsections:
 *
 * D) Public Child key
 *
 * @param extendedKey - extend public key (p, c) where p is the public key and c is the chain code. Total 64 bytes
 * @param index - unharden index (i < 2^31) of the child key
 * @param g - Defines how many bits to zero in the left 32 bytes of the child key. Standard BIP32-ed25519 derivations use 32 bits.
 * @returns - 64 bytes, being the 32 bytes of the child key (the new public key) followed by the 32 bytes of the chain code
 */
function deriveChildNodePublic(extendedKey, index, g = 9) {
    if (index > 0x80000000)
        throw new Error("can not derive public key with harden");
    const pk = Buffer.from(extendedKey.subarray(0, 32));
    const cc = Buffer.from(extendedKey.subarray(32, 64));
    const data = Buffer.allocUnsafe(1 + 32 + 4);
    data.writeUInt32LE(index, 1 + 32);
    pk.copy(data, 1);
    // Step 1: Compute Z
    data[0] = 0x02;
    const z = crypto.createHmac("sha512", cc).update(data).digest();
    // Step 2: Compute child public key
    const zL = trunc_256_minus_g_bits(z.subarray(0, 32), g);
    // ######################################
    // Standard BIP32-ed25519 derivation
    // #######################################
    // zL = 8 * 28bytesOf(z_left_hand_side)
    // ######################################
    // Chris Peikert's ammendment to BIP32-ed25519 derivation
    // #######################################
    // zL = 8 * trunc_256_minus_g_bits (z_left_hand_side, g)
    const left = new BN(zL, 16, "le")
        .mul(new BN(8))
        .toArrayLike(Buffer, "le", 32);
    const p = lws.crypto_scalarmult_ed25519_base_noclamp(left);
    // Step 3: Compute child chain code
    data[0] = 0x03;
    const fullChildChainCode = crypto.createHmac("sha512", cc)
        .update(data)
        .digest();
    const childChainCode = fullChildChainCode.subarray(32, 64);
    return new Uint8Array(Buffer.concat([lws.crypto_core_ed25519_add(p, pk), childChainCode]));
}
/**
 *
 * @see section V. BIP32-Ed25519: Specification
 *
 * @param kl - The scalar
 * @param cc - chain code
 * @param index - non-hardened ( < 2^31 ) index
 * @returns - (z, c) where z is the 64-byte child key and c is the chain code
 */
function derivedNonHardened(kl, cc, index) {
    const data = Buffer.allocUnsafe(1 + 32 + 4);
    data.writeUInt32LE(index, 1 + 32);
    var pk = Buffer.from(lws.crypto_scalarmult_ed25519_base_noclamp(kl));
    pk.copy(data, 1);
    data[0] = 0x02;
    const z = crypto.createHmac("sha512", cc).update(data).digest();
    data[0] = 0x03;
    const fullChildChainCode = crypto.createHmac("sha512", cc)
        .update(data)
        .digest();
    const childChainCode = fullChildChainCode.subarray(32, 64);
    return { z, childChainCode };
}
/**
 *
 * @see section V. BIP32-Ed25519: Specification
 *
 * @param kl - The scalar (a.k.a private key)
 * @param kr - the right 32 bytes of the root key
 * @param cc - chain code
 * @param index - hardened ( >= 2^31 ) index
 * @returns - (z, c) where z is the 64-byte child key and c is the chain code
 */
function deriveHardened(kl, kr, cc, index) {
    const data = Buffer.allocUnsafe(1 + 64 + 4);
    data.writeUInt32LE(index, 1 + 64);
    Buffer.from(kl).copy(data, 1);
    Buffer.from(kr).copy(data, 1 + 32);
    data[0] = 0x00;
    const z = crypto.createHmac("sha512", cc).update(data).digest();
    data[0] = 0x01;
    const fullChildChainCode = crypto.createHmac("sha512", cc)
        .update(data)
        .digest();
    const childChainCode = fullChildChainCode.subarray(32, 64);
    return { z, childChainCode };
}

/**
 *
 */
exports.KeyContext = void 0;
(function (KeyContext) {
    KeyContext[KeyContext["Address"] = 0] = "Address";
    KeyContext[KeyContext["Identity"] = 1] = "Identity";
    KeyContext[KeyContext["Cardano"] = 2] = "Cardano";
    KeyContext[KeyContext["TESTVECTOR_1"] = 3] = "TESTVECTOR_1";
    KeyContext[KeyContext["TESTVECTOR_2"] = 4] = "TESTVECTOR_2";
    KeyContext[KeyContext["TESTVECTOR_3"] = 5] = "TESTVECTOR_3";
})(exports.KeyContext || (exports.KeyContext = {}));
exports.BIP32DerivationType = void 0;
(function (BIP32DerivationType) {
    // standard Ed25519 bip32 derivations based of: https://acrobat.adobe.com/id/urn:aaid:sc:EU:04fe29b0-ea1a-478b-a886-9bb558a5242a
    // Defines 32 bits to be zeroed from each derived zL
    BIP32DerivationType[BIP32DerivationType["Khovratovich"] = 32] = "Khovratovich";
    // Derivations based on Peikert's ammendments to the original BIP32-Ed25519
    // Picking only 9 bits to be zeroed from each derived zL
    BIP32DerivationType[BIP32DerivationType["Peikert"] = 9] = "Peikert";
})(exports.BIP32DerivationType || (exports.BIP32DerivationType = {}));
exports.Encoding = void 0;
(function (Encoding) {
    Encoding["MSGPACK"] = "msgpack";
    Encoding["BASE64"] = "base64";
    Encoding["NONE"] = "none";
})(exports.Encoding || (exports.Encoding = {}));
const harden = (num) => 2147483648 + num;
function GetBIP44PathFromContext(context, account, key_index) {
    switch (context) {
        case exports.KeyContext.Address:
            return [harden(44), harden(283), harden(account), 0, key_index];
        case exports.KeyContext.Identity:
            return [harden(44), harden(0), harden(account), 0, key_index];
        default:
            throw new Error("Invalid context");
    }
}
const ERROR_BAD_DATA = new Error("Invalid Data");
const ERROR_TAGS_FOUND = new Error("Transactions tags found");
class XHDWalletAPI {
    constructor() { }
    /**
     * Derives a child key from the root key based on BIP44 path
     *
     * @param rootKey - root key in extended format (kL, kR, c). It should be 96 bytes long
     * @param bip44Path - BIP44 path (m / purpose' / coin_type' / account' / change / address_index). The ' indicates that the value is hardened
     * @param isPrivate  - if true, return the private key, otherwise return the public key
     * @returns - The extended private key (kL, kR, chainCode) or the extended public key (pub, chainCode)
     */
    async deriveKey(rootKey, bip44Path, isPrivate = true, derivationType) {
        await lws.ready; // libsodium
        // Pick `g`, which is amount of bits zeroed from each derived node
        const g = derivationType === exports.BIP32DerivationType.Peikert ? 9 : 32;
        for (let i = 0; i < bip44Path.length; i++) {
            rootKey = await deriveChildNodePrivate(rootKey, bip44Path[i], g);
        }
        if (isPrivate)
            return rootKey;
        // extended public key
        // [public] [nodeCC]
        return new Uint8Array(Buffer.concat([
            lws.crypto_scalarmult_ed25519_base_noclamp(rootKey.subarray(0, 32)),
            rootKey.subarray(64, 96),
        ]));
    }
    /**
     *
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @returns - public key 32 bytes
     */
    async keyGen(rootKey, context, account, keyIndex, derivationType = exports.BIP32DerivationType.Peikert) {
        await lws.ready; // libsodium
        const bip44Path = GetBIP44PathFromContext(context, account, keyIndex);
        const extendedKey = await this.deriveKey(rootKey, bip44Path, false, derivationType);
        return extendedKey.subarray(0, 32); // only public key
    }
    /**
     * Raw Signing function called by signData and signTransaction
     *
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     *
     * Edwards-Curve Digital Signature Algorithm (EdDSA)
     *
     * @param bip44Path
     * - BIP44 path (m / purpose' / coin_type' / account' / change / address_index)
     * @param data
     * - data to be signed in raw bytes
     *
     * @returns
     * - signature holding R and S, totally 64 bytes
     */
    async rawSign(rootKey, bip44Path, data, derivationType) {
        await lws.ready; // libsodium
        const raw = await this.deriveKey(rootKey, bip44Path, true, derivationType);
        const scalar = raw.slice(0, 32);
        const kR = raw.slice(32, 64);
        // \(1): pubKey = scalar * G (base point, no clamp)
        const publicKey = lws.crypto_scalarmult_ed25519_base_noclamp(scalar);
        // \(2): h = hash(c || msg) mod q
        const r = lws.crypto_core_ed25519_scalar_reduce(lws.crypto_hash_sha512(Buffer.concat([kR, data])));
        // \(4):  R = r * G (base point, no clamp)
        const R = lws.crypto_scalarmult_ed25519_base_noclamp(r);
        // h = hash(R || pubKey || msg) mod q
        let h = lws.crypto_core_ed25519_scalar_reduce(lws.crypto_hash_sha512(Buffer.concat([R, publicKey, data])));
        // \(5): S = (r + h * k) mod q
        const S = lws.crypto_core_ed25519_scalar_add(r, lws.crypto_core_ed25519_scalar_mul(h, scalar));
        return Buffer.concat([R, S]);
    }
    /**
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     *
     *  Edwards-Curve Digital Signature Algorithm (EdDSA)
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @param data - data to be signed in raw bytes
     * @param metadata - metadata object that describes how `data` was encoded and what schema to use to validate against
     * @param derivationType
     * - BIP32 derivation type, defines if it's standard Ed25519 or Peikert's ammendment to BIP32-Ed25519
     *
     * @returns - signature holding R and S, totally 64 bytes
     * */
    async signData(rootKey, context, account, keyIndex, data, metadata, derivationType = exports.BIP32DerivationType.Peikert) {
        // validate data
        const result = this.validateData(data, metadata);
        if (result instanceof Error) {
            // decoding errors
            throw result;
        }
        if (!result) {
            // failed schema validation
            throw ERROR_BAD_DATA;
        }
        await lws.ready; // libsodium
        const bip44Path = GetBIP44PathFromContext(context, account, keyIndex);
        return await this.rawSign(rootKey, bip44Path, data, derivationType);
    }
    /**
     * Sign Algorand transaction
     * @param context
     * - context of the key (i.e Address, Identity)
     * @param account
     * - account number. This value will be hardened as part of BIP44
     * @param keyIndex
     * - key index. This value will be a SOFT derivation as part of BIP44.
     * @param prefixEncodedTx
     * - Encoded transaction object
     * @param derivationType
     * - BIP32 derivation type, defines if it's standard Ed25519 or Peikert's ammendment to BIP32-Ed25519
     *
     * @returns sig
     * - Raw bytes signature
     */
    async signAlgoTransaction(rootKey, context, account, keyIndex, prefixEncodedTx, derivationType = exports.BIP32DerivationType.Peikert) {
        await lws.ready; // libsodium
        const bip44Path = GetBIP44PathFromContext(context, account, keyIndex);
        const sig = await this.rawSign(rootKey, bip44Path, prefixEncodedTx, derivationType);
        return sig;
    }
    /**
     * SAMPLE IMPLEMENTATION to show how to validate data with encoding and schema, using base64 as an example
     *
     * @param message
     * @param metadata
     * @returns
     */
    validateData(message, metadata) {
        // Check that decoded doesn't include the following prefixes: TX, MX, progData, Program
        // These prefixes are reserved for the protocol
        if (this.hasAlgorandTags(message)) {
            return ERROR_TAGS_FOUND;
        }
        let decoded;
        switch (metadata.encoding) {
            case exports.Encoding.BASE64:
                decoded = new Uint8Array(Buffer.from(Buffer.from(message).toString(), "base64"));
                break;
            case exports.Encoding.MSGPACK:
                decoded = msgpack__namespace.decode(message);
                break;
            case exports.Encoding.NONE:
                decoded = message;
                break;
            default:
                throw new Error("Invalid encoding");
        }
        // validate with schema
        const ajv = new Ajv();
        const validate = ajv.compile(metadata.schema);
        const valid = validate(decoded);
        if (!valid)
            console.log(ajv.errors);
        return valid;
    }
    /**
     * Detect if the message has Algorand protocol specific tags
     *
     * @param message - raw bytes of the message
     * @returns - true if message has Algorand protocol specific tags, false otherwise
     */
    hasAlgorandTags(message) {
        // Check that decoded doesn't include the following prefixes
        // Prefixes taken from go-algorand node software code
        // https://github.com/algorand/go-algorand/blob/master/protocol/hash.go
        const prefixes = [
            "appID",
            "arc",
            "aB",
            "aD",
            "aO",
            "aP",
            "aS",
            "AS",
            "B256",
            "BH",
            "BR",
            "CR",
            "GE",
            "KP",
            "MA",
            "MB",
            "MX",
            "NIC",
            "NIR",
            "NIV",
            "NPR",
            "OT1",
            "OT2",
            "PF",
            "PL",
            "Program",
            "ProgData",
            "PS",
            "PK",
            "SD",
            "SpecialAddr",
            "STIB",
            "spc",
            "spm",
            "spp",
            "sps",
            "spv",
            "TE",
            "TG",
            "TL",
            "TX",
            "VO",
        ];
        for (const prefix of prefixes) {
            if (Buffer.from(message.subarray(0, prefix.length)).toString("ascii") ===
                prefix) {
                return true;
            }
        }
        return false;
    }
    /**
     * Wrapper around libsodium basica signature verification
     *
     * Any lib or system that can verify EdDSA signatures can be used
     *
     * @param signature - raw 64 bytes signature (R, S)
     * @param message - raw bytes of the message
     * @param publicKey - raw 32 bytes public key (x,y)
     * @returns true if signature is valid, false otherwise
     */
    async verifyWithPublicKey(signature, message, publicKey) {
        await lws.ready; // libsodium
        return lws.crypto_sign_verify_detached(signature, message, publicKey);
    }
    /**
     * Function to perform ECDH against a provided public key
     *
     * ECDH reference link: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
     *
     * It creates a shared secret between two parties. Each party only needs to be aware of the other's public key.
     * This symmetric secret can be used to derive a symmetric key for encryption and decryption. Creating a private channel between the two parties.
     *
     * @param context - context of the key (i.e Address, Identity)
     * @param account - account number. This value will be hardened as part of BIP44
     * @param keyIndex - key index. This value will be a SOFT derivation as part of BIP44.
     * @param otherPartyPub - raw 32 bytes public key of the other party
     * @param meFirst - defines the order in which the keys will be considered for the shared secret. If true, our key will be used first, otherwise the other party's key will be used first
     * @returns - raw 32 bytes shared secret
     */
    async ECDH(rootKey, context, account, keyIndex, otherPartyPub, meFirst, derivationType = exports.BIP32DerivationType.Peikert) {
        await lws.ready;
        const bip44Path = GetBIP44PathFromContext(context, account, keyIndex);
        const childKey = await this.deriveKey(rootKey, bip44Path, true, derivationType);
        const scalar = childKey.slice(0, 32);
        // our public key is derived from the private key
        const ourPub = lws.crypto_scalarmult_ed25519_base_noclamp(scalar);
        // convert from ed25519 to curve25519
        const ourPubCurve25519 = lws.crypto_sign_ed25519_pk_to_curve25519(ourPub);
        const otherPartyPubCurve25519 = lws.crypto_sign_ed25519_pk_to_curve25519(otherPartyPub);
        // find common point
        const sharedPoint = lws.crypto_scalarmult(scalar, otherPartyPubCurve25519);
        let concatenation;
        if (meFirst) {
            concatenation = Buffer.concat([
                sharedPoint,
                ourPubCurve25519,
                otherPartyPubCurve25519,
            ]);
        }
        else {
            concatenation = Buffer.concat([
                sharedPoint,
                otherPartyPubCurve25519,
                ourPubCurve25519,
            ]);
        }
        return lws.crypto_generichash(32, new Uint8Array(concatenation));
    }
}

exports.ERROR_BAD_DATA = ERROR_BAD_DATA;
exports.ERROR_TAGS_FOUND = ERROR_TAGS_FOUND;
exports.XHDWalletAPI = XHDWalletAPI;
exports.deriveChildNodePublic = deriveChildNodePublic;
exports.fromSeed = fromSeed;
exports.harden = harden;

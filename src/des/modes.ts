/**
 * ECB and CBC over the real DES block cipher, with the data limit enforced.
 *
 * ## Why a mode module has a policy in it
 *
 * A 64-bit block cipher has a birthday bound measured in BLOCKS, and in CBC
 * that bound is not an abstraction: two equal ciphertext blocks hand an
 * eavesdropper the XOR of the two plaintext blocks that produced them
 * (`sweet32.ts` derives it). So "how much may I encrypt under one key" is a
 * property of the mode, not of the deployment, and refusing to go past it is
 * the library's job. `cbcEncrypt` refuses with BLOCK_SIZE_EXCEEDED.
 *
 * The default limit is the one NIST set for TDEA in SP 800-67 Rev. 2 §3.4:
 * 2^20 64-bit blocks — 8 MiB — per key bundle. Before 2017 the limit was 2^32
 * blocks, about 32 GiB, and that is precisely the number Sweet32 collected
 * against. SP 800-67 Rev. 2 has itself since been withdrawn (2024-01-01) and
 * TDEA encryption has been disallowed since the end of 2023; the limit is cited
 * here as the historical policy the failure code models, not as live guidance.
 * The dates are in `vectors.ts` and the README's "What It Is".
 *
 * NOT PRODUCTION CRYPTOGRAPHY: single DES is broken, CBC here is unauthenticated,
 * and unauthenticated CBC is separately a bad idea for reasons this lab does not
 * cover (see the padding-oracle demo in the suite).
 */
import { decryptBlock, encryptBlock } from './des';
import { xorBytes } from './bytes';
import type { Result } from './types';
import { fail, ok } from './types';

/** The block size of DES, in bytes. The whole lab is about this number. */
export const BLOCK_BYTES = 8;

export interface DataLimit {
  /** Maximum number of 64-bit blocks under one key. */
  readonly maxBlocks: number;
  /** Short label for the UI. */
  readonly label: string;
  /** Where the number comes from. */
  readonly citation: string;
}

/**
 * SP 800-67 Rev. 2 §3.4: at most 2^20 blocks per three-key TDEA key bundle.
 * 2^20 blocks x 8 bytes = 8 MiB.
 */
export const LIMIT_SP800_67R2: DataLimit = {
  maxBlocks: 2 ** 20,
  label: '2^20 blocks (8 MiB)',
  citation: 'NIST SP 800-67 Rev. 2 §3.4 (withdrawn 2024-01-01)',
};

/**
 * The pre-2017 limit, 2^32 blocks (~32 GiB) — the figure Sweet32 was measured
 * against. Present as a comparison only; nothing in this lab encrypts that much.
 */
export const LIMIT_LEGACY_2_32: DataLimit = {
  maxBlocks: 2 ** 32,
  label: '2^32 blocks (32 GiB)',
  citation: 'the pre-2017 TDEA limit, withdrawn in response to Sweet32',
};

/** A limit high enough not to interfere — the deliberately-unbounded mode. */
export const LIMIT_NONE: DataLimit = {
  maxBlocks: Number.MAX_SAFE_INTEGER,
  label: 'no limit (deliberately broken)',
  citation: 'not a real policy — present so the exhibit can show what removing the limit permits',
};

/**
 * The data-limit policy, on its own.
 *
 * `cbcEncrypt` calls this, and so does the exhibit's limit meter — which is the
 * point of factoring it out. A meter that reimplemented the rule could drift
 * from the rule the cipher enforces and nobody would notice; this way the
 * reading on screen and the refusal in the cipher are the same function. The
 * meter can also ask about block counts far too large to allocate, which is how
 * a learner gets to see the 2^32 answer without a 32 GiB buffer.
 */
export function checkDataLimit(blockCount: number, limit: DataLimit): Result<number> {
  if (blockCount > limit.maxBlocks) {
    return fail(
      'BLOCK_SIZE_EXCEEDED',
      `${blockCount.toLocaleString()} blocks exceeds the ${limit.label} data limit for a 64-bit block cipher under one key.`,
      limit.citation
    );
  }
  return ok(blockCount);
}

/** One CBC block, with every value the chaining consumed and produced. */
export interface CbcBlock {
  readonly index: number;
  /** P_i */
  readonly plaintext: Uint8Array;
  /** C_(i-1), or the IV for i = 0. */
  readonly chainIn: Uint8Array;
  /** P_i XOR C_(i-1) — what actually enters the block cipher. */
  readonly cipherInput: Uint8Array;
  /** C_i */
  readonly ciphertext: Uint8Array;
}

export interface CbcResult {
  readonly iv: Uint8Array;
  readonly blocks: readonly CbcBlock[];
  readonly ciphertext: Uint8Array;
}

function splitBlocks(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let at = 0; at < data.length; at += BLOCK_BYTES) out.push(data.subarray(at, at + BLOCK_BYTES));
  return out;
}

/**
 * CBC encryption: C_i = E_K(P_i XOR C_(i-1)), C_(-1) = IV.
 *
 * Refuses BLOCK_SIZE_EXCEEDED before encrypting anything, so the failure is a
 * policy decision rather than a partial result. Requires an exact multiple of
 * the block size — padding is the caller's business and is deliberately not
 * hidden in here.
 */
export function cbcEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  limit: DataLimit = LIMIT_SP800_67R2
): Result<CbcResult> {
  if (iv.length !== BLOCK_BYTES) {
    return fail('BLOCK_LENGTH_INVALID', `The IV must be ${BLOCK_BYTES} bytes; got ${iv.length}.`);
  }
  if (plaintext.length % BLOCK_BYTES !== 0) {
    return fail(
      'BLOCK_LENGTH_INVALID',
      `CBC needs a whole number of ${BLOCK_BYTES}-byte blocks; ${plaintext.length} bytes is ${plaintext.length % BLOCK_BYTES} over.`
    );
  }
  const count = plaintext.length / BLOCK_BYTES;
  const allowed = checkDataLimit(count, limit);
  if (!allowed.ok) return allowed;
  const blocks: CbcBlock[] = [];
  const ciphertext = new Uint8Array(plaintext.length);
  let chain = iv;
  splitBlocks(plaintext).forEach((p, index) => {
    const cipherInput = xorBytes(p, chain);
    const c = encryptBlock(key, cipherInput);
    ciphertext.set(c, index * BLOCK_BYTES);
    blocks.push({ index, plaintext: p, chainIn: chain, cipherInput, ciphertext: c });
    chain = c;
  });
  return ok({ iv, blocks, ciphertext });
}

/** CBC decryption: P_i = D_K(C_i) XOR C_(i-1). */
export function cbcDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Result<Uint8Array> {
  if (iv.length !== BLOCK_BYTES) {
    return fail('BLOCK_LENGTH_INVALID', `The IV must be ${BLOCK_BYTES} bytes; got ${iv.length}.`);
  }
  if (ciphertext.length % BLOCK_BYTES !== 0) {
    return fail(
      'BLOCK_LENGTH_INVALID',
      `CBC ciphertext must be a whole number of ${BLOCK_BYTES}-byte blocks; got ${ciphertext.length} bytes.`
    );
  }
  const out = new Uint8Array(ciphertext.length);
  let chain = iv;
  splitBlocks(ciphertext).forEach((c, index) => {
    out.set(xorBytes(decryptBlock(key, c), chain), index * BLOCK_BYTES);
    chain = c;
  });
  return ok(out);
}

/**
 * ECB, present only because the CAVP known-answer vectors are single-block ECB
 * and because the "same ciphertext for the same plaintext" property is worth
 * one sentence in the mode discussion. Never a default anywhere in this lab.
 */
export function ecbEncrypt(key: Uint8Array, plaintext: Uint8Array): Result<Uint8Array> {
  if (plaintext.length % BLOCK_BYTES !== 0) {
    return fail('BLOCK_LENGTH_INVALID', `ECB needs whole ${BLOCK_BYTES}-byte blocks; got ${plaintext.length}.`);
  }
  const out = new Uint8Array(plaintext.length);
  splitBlocks(plaintext).forEach((p, i) => out.set(encryptBlock(key, p), i * BLOCK_BYTES));
  return ok(out);
}

/** PKCS#7 padding to the DES block size. */
export function pkcs7Pad(data: Uint8Array): Uint8Array {
  const padding = BLOCK_BYTES - (data.length % BLOCK_BYTES);
  const out = new Uint8Array(data.length + padding);
  out.set(data, 0);
  out.fill(padding, data.length);
  return out;
}

/** Strict PKCS#7 unpadding. Refuses malformed padding rather than guessing. */
export function pkcs7Unpad(data: Uint8Array): Result<Uint8Array> {
  if (data.length === 0 || data.length % BLOCK_BYTES !== 0) {
    return fail('BLOCK_LENGTH_INVALID', `Padded data must be a non-empty multiple of ${BLOCK_BYTES} bytes.`);
  }
  const padding = data[data.length - 1];
  if (padding < 1 || padding > BLOCK_BYTES) {
    return fail('BLOCK_LENGTH_INVALID', `Padding byte 0x${padding.toString(16)} is not in 1..${BLOCK_BYTES}.`);
  }
  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) return fail('BLOCK_LENGTH_INVALID', `Padding byte ${i} is 0x${data[i].toString(16)}, expected 0x${padding.toString(16)}.`);
  }
  return ok(data.subarray(0, data.length - padding));
}

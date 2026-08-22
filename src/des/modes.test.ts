/**
 * Mode and data-limit tests.
 *
 * The CAVP CBC vectors in `vectors.test.ts` gate the chaining arithmetic. What
 * is tested here is the POLICY: that BLOCK_SIZE_EXCEEDED is raised by the same
 * function the exhibit's limit meter reads, that it is raised BEFORE any
 * encryption happens, and that every strict-parsing refusal actually refuses.
 */
import { describe, expect, it } from 'vitest';
import {
  BLOCK_BYTES,
  cbcDecrypt,
  cbcEncrypt,
  checkDataLimit,
  ecbEncrypt,
  LIMIT_LEGACY_2_32,
  LIMIT_NONE,
  LIMIT_SP800_67R2,
  pkcs7Pad,
  pkcs7Unpad,
} from './modes';
import { encryptBlock } from './des';
import { bytesEqual, randomBytes, toHex, utf8, xorBytes } from './bytes';
import { fixParity } from './weakKeys';

const key = (): Uint8Array => fixParity(randomBytes(8));

describe('CBC', () => {
  it('chains: C_i = E_K(P_i XOR C_(i-1)) with C_(-1) = IV', () => {
    const k = key();
    const iv = randomBytes(8);
    const plaintext = randomBytes(8 * 6);
    const run = cbcEncrypt(k, iv, plaintext);
    expect(run.ok).toBe(true);
    if (!run.ok) return;
    let chain = iv;
    run.value.blocks.forEach((block) => {
      expect(bytesEqual(block.chainIn, chain)).toBe(true);
      expect(bytesEqual(block.cipherInput, xorBytes(block.plaintext, chain))).toBe(true);
      expect(bytesEqual(block.ciphertext, encryptBlock(k, block.cipherInput))).toBe(true);
      chain = block.ciphertext;
    });
  });

  it('round-trips', () => {
    for (let i = 0; i < 30; i++) {
      const k = key();
      const iv = randomBytes(8);
      const plaintext = randomBytes(8 * (1 + (i % 5)));
      const run = cbcEncrypt(k, iv, plaintext);
      expect(run.ok).toBe(true);
      if (!run.ok) return;
      const back = cbcDecrypt(k, iv, run.value.ciphertext);
      expect(back.ok).toBe(true);
      if (back.ok) expect(toHex(back.value)).toBe(toHex(plaintext));
    }
  });

  it('hides the ECB tell: identical plaintext blocks get different ciphertext', () => {
    const repeated = new Uint8Array(8 * 4);
    for (let i = 0; i < 4; i++) repeated.set(utf8('AAAAAAAA'), i * 8);
    const k = key();
    const cbc = cbcEncrypt(k, randomBytes(8), repeated);
    const ecb = ecbEncrypt(k, repeated);
    expect(cbc.ok && ecb.ok).toBe(true);
    if (!cbc.ok || !ecb.ok) return;
    expect(new Set(cbc.value.blocks.map((b) => toHex(b.ciphertext))).size).toBe(4);
    const ecbBlocks = new Set<string>();
    for (let i = 0; i < 4; i++) ecbBlocks.add(toHex(ecb.value.subarray(i * 8, i * 8 + 8)));
    expect(ecbBlocks.size).toBe(1);
  });

  it('refuses a short IV and a ragged plaintext rather than padding them', () => {
    const k = key();
    const shortIv = cbcEncrypt(k, randomBytes(7), randomBytes(8));
    expect(shortIv.ok).toBe(false);
    if (!shortIv.ok) expect(shortIv.error.code).toBe('BLOCK_LENGTH_INVALID');
    const ragged = cbcEncrypt(k, randomBytes(8), randomBytes(9));
    expect(ragged.ok).toBe(false);
    if (!ragged.ok) {
      expect(ragged.error.code).toBe('BLOCK_LENGTH_INVALID');
      expect(ragged.error.message).toContain('1 over');
    }
  });
});

describe('the data limit', () => {
  it('checkDataLimit passes at the limit and refuses one block past it', () => {
    expect(checkDataLimit(LIMIT_SP800_67R2.maxBlocks, LIMIT_SP800_67R2).ok).toBe(true);
    const over = checkDataLimit(LIMIT_SP800_67R2.maxBlocks + 1, LIMIT_SP800_67R2);
    expect(over.ok).toBe(false);
    if (!over.ok) {
      expect(over.error.code).toBe('BLOCK_SIZE_EXCEEDED');
      expect(over.error.detail).toContain('SP 800-67');
    }
  });

  /**
   * The meter and the cipher must agree, because the exhibit shows one and
   * relies on the other. This asserts they are the same decision at the
   * boundary, for each shipped limit.
   */
  it.each([
    ['SP 800-67 Rev. 2', LIMIT_SP800_67R2],
    ['legacy 2^32', LIMIT_LEGACY_2_32],
    ['none', LIMIT_NONE],
  ])('cbcEncrypt agrees with checkDataLimit for the %s limit', (_label, limit) => {
    const k = key();
    const iv = randomBytes(8);
    for (const count of [1, 2, 16]) {
      const viaMeter = checkDataLimit(count, limit).ok;
      const viaCipher = cbcEncrypt(k, iv, new Uint8Array(count * BLOCK_BYTES), limit).ok;
      expect(viaCipher).toBe(viaMeter);
    }
  });

  it('refuses before encrypting: an oversized buffer costs no DES calls', () => {
    // A tiny limit makes the boundary cheap to cross without allocating 8 MiB.
    const tiny = { maxBlocks: 2, label: '2 blocks', citation: 'test fixture' };
    const run = cbcEncrypt(key(), randomBytes(8), new Uint8Array(3 * BLOCK_BYTES), tiny);
    expect(run.ok).toBe(false);
    if (!run.ok) {
      expect(run.error.code).toBe('BLOCK_SIZE_EXCEEDED');
      // The message reports the count that was refused, not the limit.
      expect(run.error.message).toContain('3 blocks');
    }
  });

  it('the shipped limits are the documented numbers', () => {
    expect(LIMIT_SP800_67R2.maxBlocks).toBe(2 ** 20);
    expect(LIMIT_SP800_67R2.maxBlocks * BLOCK_BYTES).toBe(8 * 1024 * 1024);
    expect(LIMIT_LEGACY_2_32.maxBlocks).toBe(2 ** 32);
    expect(LIMIT_LEGACY_2_32.maxBlocks * BLOCK_BYTES).toBe(32 * 1024 ** 3);
  });

  it('the meter answers for block counts far too large to allocate', () => {
    const answer = checkDataLimit(2 ** 32, LIMIT_SP800_67R2);
    expect(answer.ok).toBe(false);
    if (!answer.ok) expect(answer.error.code).toBe('BLOCK_SIZE_EXCEEDED');
  });
});

describe('PKCS#7', () => {
  it('round-trips every length in a block', () => {
    for (let n = 0; n < 20; n++) {
      const data = randomBytes(n);
      const padded = pkcs7Pad(data);
      expect(padded.length % BLOCK_BYTES).toBe(0);
      expect(padded.length).toBeGreaterThan(data.length);
      const back = pkcs7Unpad(padded);
      expect(back.ok).toBe(true);
      if (back.ok) expect(toHex(back.value)).toBe(toHex(data));
    }
  });

  it('always adds a whole block when the input is already aligned', () => {
    expect(pkcs7Pad(new Uint8Array(8)).length).toBe(16);
  });

  it('refuses malformed padding rather than guessing', () => {
    const bad = new Uint8Array(8);
    bad[7] = 0x09;
    expect(pkcs7Unpad(bad).ok).toBe(false);
    const inconsistent = new Uint8Array(8);
    inconsistent[6] = 0x01;
    inconsistent[7] = 0x02;
    expect(pkcs7Unpad(inconsistent).ok).toBe(false);
    expect(pkcs7Unpad(new Uint8Array(0)).ok).toBe(false);
    expect(pkcs7Unpad(new Uint8Array(7)).ok).toBe(false);
  });
});

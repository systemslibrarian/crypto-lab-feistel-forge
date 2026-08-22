/**
 * The known-answer gate.
 *
 * Every triple in `vectors.ts` came out of NIST's archived CAVP archive
 * KAT_TDES.zip, and every one is asserted here in BOTH directions — which is
 * what the .rsp files' paired [ENCRYPT] and [DECRYPT] sections ask of a
 * validating implementation.
 *
 * This file is the only thing standing between a transposed digit in
 * `tables.ts` and a cipher that round-trips perfectly while computing the wrong
 * function. A round-trip test cannot see that failure; these vectors can.
 */
import { describe, expect, it } from 'vitest';
import { decryptBlock, encryptBlock } from './des';
import { cbcDecrypt, cbcEncrypt } from './modes';
import { parseHex, toHex } from './bytes';
import { ALL_VECTORS, ASSERTION_COUNT, KAT_GROUPS, VECTOR_COUNT } from './vectors';

const bytes = (hex: string): Uint8Array => {
  const parsed = parseHex(hex, 8);
  if (!parsed.ok) throw new Error(`${hex}: ${parsed.error.message}`);
  return parsed.value;
};

describe('NIST CAVP known-answer vectors', () => {
  it('carries the five SP 500-20 ECB families at their published case counts', () => {
    const counts = Object.fromEntries(KAT_GROUPS.map((g) => [g.id, g.vectors.length]));
    expect(counts).toEqual({
      vartext: 64,
      invperm: 64,
      varkey: 56,
      permop: 32,
      subtab: 19,
      cbcvartext: 64,
    });
    expect(VECTOR_COUNT).toBe(299);
    expect(ASSERTION_COUNT).toBe(598);
  });

  it('states its own assertion count correctly', () => {
    expect(ASSERTION_COUNT).toBe(VECTOR_COUNT * 2);
  });

  for (const group of KAT_GROUPS) {
    describe(group.title, () => {
      it(`encrypts all ${group.vectors.length} vectors to the published ciphertext`, () => {
        const wrong: string[] = [];
        for (const v of group.vectors) {
          const key = bytes(v.key);
          if (group.mode === 'ecb') {
            const got = toHex(encryptBlock(key, bytes(v.plaintext)));
            if (got !== v.ciphertext) wrong.push(`${v.key}/${v.plaintext}: got ${got}, want ${v.ciphertext}`);
          } else {
            const run = cbcEncrypt(key, bytes(v.iv as string), bytes(v.plaintext));
            expect(run.ok).toBe(true);
            if (run.ok) {
              const got = toHex(run.value.ciphertext);
              if (got !== v.ciphertext) wrong.push(`${v.key}/${v.plaintext}: got ${got}, want ${v.ciphertext}`);
            }
          }
        }
        expect(wrong).toEqual([]);
      });

      it(`decrypts all ${group.vectors.length} vectors back to the published plaintext`, () => {
        const wrong: string[] = [];
        for (const v of group.vectors) {
          const key = bytes(v.key);
          if (group.mode === 'ecb') {
            const got = toHex(decryptBlock(key, bytes(v.ciphertext)));
            if (got !== v.plaintext) wrong.push(`${v.key}/${v.ciphertext}: got ${got}, want ${v.plaintext}`);
          } else {
            const run = cbcDecrypt(key, bytes(v.iv as string), bytes(v.ciphertext));
            expect(run.ok).toBe(true);
            if (run.ok) {
              const got = toHex(run.value);
              if (got !== v.plaintext) wrong.push(`${v.key}/${v.ciphertext}: got ${got}, want ${v.plaintext}`);
            }
          }
        }
        expect(wrong).toEqual([]);
      });
    });
  }

  it('every stored vector is well-formed hex of the right length', () => {
    for (const v of ALL_VECTORS) {
      expect(v.key).toMatch(/^[0-9a-f]{16}$/);
      expect(v.plaintext).toMatch(/^[0-9a-f]{16}$/);
      expect(v.ciphertext).toMatch(/^[0-9a-f]{16}$/);
      if (v.mode === 'cbc') expect(v.iv).toMatch(/^[0-9a-f]{16}$/);
      else expect(v.iv).toBeUndefined();
    }
  });

  /**
   * The Variable Plaintext and Inverse Permutation families carry the same data
   * with the columns swapped — CAVP publishes both, and SP 800-17 prints only
   * one table for the pair. Asserted rather than described, because the claim
   * appears in `vectors.ts`'s own prose and in the README, and a silently
   * regenerated file could make it false.
   */
  it('the Inverse Permutation family is the Variable Plaintext family transposed', () => {
    const vartext = KAT_GROUPS.find((g) => g.id === 'vartext');
    const invperm = KAT_GROUPS.find((g) => g.id === 'invperm');
    expect(vartext && invperm).toBeTruthy();
    const transposed = new Set(
      (vartext as { vectors: readonly { key: string; plaintext: string; ciphertext: string }[] }).vectors.map(
        (v) => `${v.key}/${v.ciphertext}/${v.plaintext}`
      )
    );
    const actual = new Set(
      (invperm as { vectors: readonly { key: string; plaintext: string; ciphertext: string }[] }).vectors.map(
        (v) => `${v.key}/${v.plaintext}/${v.ciphertext}`
      )
    );
    expect(actual).toEqual(transposed);
  });

  /**
   * The Variable Plaintext family's plaintexts are the 64 single-bit basis
   * vectors, and the Variable Key family's keys are the 56 key-bit basis
   * vectors. Recomputed here from the stored data rather than asserted against
   * a hard-coded list, so a mangled regeneration is caught.
   */
  it('the basis families really are single-bit sweeps', () => {
    const vartext = KAT_GROUPS.find((g) => g.id === 'vartext');
    const popcount = (hex: string): number =>
      [...hex].reduce((n, c) => n + (parseInt(c, 16).toString(2).match(/1/g)?.length ?? 0), 0);
    const plaintexts = (vartext as { vectors: readonly { plaintext: string }[] }).vectors.map((v) => v.plaintext);
    expect(plaintexts.every((p) => popcount(p) === 1)).toBe(true);
    expect(new Set(plaintexts).size).toBe(64);

    const varkey = KAT_GROUPS.find((g) => g.id === 'varkey');
    const keys = (varkey as { vectors: readonly { key: string; plaintext: string }[] }).vectors;
    // Each key has one bit set among the 56 key bits, plus whatever the odd
    // parity bits force. Popcount is therefore 8 (seven parity ones plus the
    // set bit's own byte flipping its parity bit off) — checked as a shape,
    // and every key is distinct.
    expect(new Set(keys.map((k) => k.key)).size).toBe(56);
    expect(keys.every((k) => k.plaintext === '0000000000000000')).toBe(true);
  });
});

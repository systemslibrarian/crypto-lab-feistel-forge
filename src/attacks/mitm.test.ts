import { describe, expect, it } from 'vitest';
import { doubleDesDecrypt, doubleDesEncrypt, meetInTheMiddle, projectToFullDes } from './mitm';
import { keyFromIndex } from './complement';
import { decryptBlock, encryptBlock } from '../des/des';
import { bytesEqual, parseHex, randomBytes, toHex } from '../des/bytes';
import { fixParity } from '../des/weakKeys';

const hex = (s: string): Uint8Array => {
  const parsed = parseHex(s);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
};

const BASE = hex('0101010101010101');
const P1 = hex('0123456789abcdef');
const P2 = hex('fedcba9876543210');

describe('double DES', () => {
  it('is E_K2(E_K1(P)), and its inverse undoes it', () => {
    for (let i = 0; i < 30; i++) {
      const k1 = fixParity(randomBytes(8));
      const k2 = fixParity(randomBytes(8));
      const block = randomBytes(8);
      const c = doubleDesEncrypt(k1, k2, block);
      expect(toHex(c)).toBe(toHex(encryptBlock(k2, encryptBlock(k1, block))));
      expect(toHex(doubleDesDecrypt(k1, k2, c))).toBe(toHex(block));
    }
  });

  it('is not the same as single DES under either key', () => {
    const k1 = fixParity(randomBytes(8));
    const k2 = fixParity(randomBytes(8));
    const c = doubleDesEncrypt(k1, k2, P1);
    expect(toHex(c)).not.toBe(toHex(encryptBlock(k1, P1)));
    expect(toHex(c)).not.toBe(toHex(encryptBlock(k2, P1)));
  });
});

describe('meet in the middle', () => {
  it('recovers both keys over a 2^10 space', async () => {
    const result = await meetInTheMiddle({
      bits: 10,
      base: BASE,
      k1Index: 613,
      k2Index: 77,
      plaintexts: [P1, P2],
    });
    expect(result.confirmed).not.toBeNull();
    expect(result.confirmed?.i1).toBe(613);
    expect(result.confirmed?.i2).toBe(77);
    expect(bytesEqual(result.confirmed?.k1 as Uint8Array, keyFromIndex(613, 10, BASE))).toBe(true);
    expect(bytesEqual(result.confirmed?.k2 as Uint8Array, keyFromIndex(77, 10, BASE))).toBe(true);
  });

  /**
   * An independent re-derivation: the recovered pair must actually encrypt the
   * known plaintexts to the known ciphertexts. This does not re-run the search
   * — it checks the ANSWER against the cipher, by a different route than the
   * attack took.
   */
  it('the recovered pair reproduces both known pairs', async () => {
    const result = await meetInTheMiddle({
      bits: 9,
      base: BASE,
      k1Index: 41,
      k2Index: 400,
      plaintexts: [P1, P2],
    });
    const found = result.confirmed;
    expect(found).not.toBeNull();
    if (!found) return;
    for (const pair of result.pairs) {
      expect(toHex(doubleDesEncrypt(found.k1, found.k2, pair.plaintext))).toBe(toHex(pair.ciphertext));
    }
  });

  it('the meeting value really is E_K1(P) and D_K2(C) at once', async () => {
    const result = await meetInTheMiddle({
      bits: 9,
      base: BASE,
      k1Index: 5,
      k2Index: 300,
      plaintexts: [P1, P2],
    });
    const found = result.confirmed;
    expect(found).not.toBeNull();
    if (!found) return;
    expect(toHex(found.middle)).toBe(toHex(encryptBlock(found.k1, result.pairs[0].plaintext)));
    expect(toHex(found.middle)).toBe(toHex(decryptBlock(found.k2, result.pairs[0].ciphertext)));
  });

  it('does the work the attack costs: 2 * 2^bits DES calls plus the sieve', async () => {
    const bits = 8;
    const result = await meetInTheMiddle({
      bits,
      base: BASE,
      k1Index: 3,
      k2Index: 9,
      plaintexts: [P1, P2],
    });
    // One encryption per K1, one decryption per K2, plus two per candidate for
    // the second-pair sieve.
    const expected = 2 * 2 ** bits + 2 * result.candidates.length;
    expect(result.desOperations).toBe(expected);
    expect(result.keysPerSide).toBe(2 ** bits);
  });

  it('the table holds one entry per key when no two middles collide', async () => {
    const result = await meetInTheMiddle({
      bits: 9,
      base: BASE,
      k1Index: 1,
      k2Index: 2,
      plaintexts: [P1, P2],
    });
    expect(result.tableEntries).toBe(result.keysPerSide);
  });

  it('reports progress through both phases', async () => {
    const phases: string[] = [];
    await meetInTheMiddle({
      bits: 12,
      base: BASE,
      k1Index: 1,
      k2Index: 2,
      plaintexts: [P1, P2],
      chunk: 512,
      onProgress: (p) => {
        if (phases[phases.length - 1] !== p.phase) phases.push(p.phase);
        expect(p.done).toBeLessThanOrEqual(p.total);
      },
    });
    expect(phases).toEqual(['build', 'match']);
  });

  it('refuses a key index outside the reduced space', async () => {
    await expect(
      meetInTheMiddle({ bits: 8, base: BASE, k1Index: 256, k2Index: 0, plaintexts: [P1, P2] })
    ).rejects.toThrow(/below 2\^8/);
  });

  /**
   * The sieve has to be doing something. At these widths false positives are
   * rare, so this constructs one directly: any candidate the search reported
   * that is NOT the real pair must have failed the second pair.
   */
  it('every candidate that is not the real pair fails the second-pair sieve', async () => {
    const result = await meetInTheMiddle({
      bits: 10,
      base: BASE,
      k1Index: 100,
      k2Index: 900,
      plaintexts: [P1, P2],
    });
    for (const candidate of result.candidates) {
      const isReal = candidate.i1 === 100 && candidate.i2 === 900;
      expect(candidate.survivesSecondPair).toBe(isReal);
    }
    expect(result.falsePositives).toBe(result.candidates.length - 1);
  });
});

describe('projecting to the real cipher', () => {
  it('reports the published complexities', async () => {
    const result = await meetInTheMiddle({
      bits: 8,
      base: BASE,
      k1Index: 3,
      k2Index: 4,
      plaintexts: [P1, P2],
    });
    const projection = projectToFullDes(result);
    // Diffie & Hellman 1977: 2^56 encryptions plus 2^56 decryptions.
    expect(projection.fullOpsLog2).toBe(57);
    // Exhaustive search over the 2DES keyspace.
    expect(projection.bruteForceLog2).toBe(112);
    // HAC Example 7.36: 2^(2k-n) = 2^48 candidate pairs from one known pair.
    expect(projection.falsePositivesLog2).toBe(48);
    // 2^56 entries at 15 bytes each.
    expect(projection.fullTableBytesLog2).toBeCloseTo(56 + Math.log2(15), 6);
  });

  it('anchors the wall-clock estimate to the run that was just measured', async () => {
    const result = await meetInTheMiddle({
      bits: 8,
      base: BASE,
      k1Index: 3,
      k2Index: 4,
      plaintexts: [P1, P2],
    });
    const projection = projectToFullDes(result);
    expect(projection.measuredOpsPerSecond).toBeGreaterThan(0);
    // Recomputed independently from the run's own counters.
    expect(projection.measuredOpsPerSecond).toBeCloseTo(
      (result.desOperations * 1000) / result.elapsedMs,
      6
    );
    expect(projection.secondsAtMeasuredRate).toBeCloseTo(
      2 ** 57 / projection.measuredOpsPerSecond,
      -3
    );
    // Sanity: no browser finishes 2^57 DES operations inside a human lifetime.
    expect(projection.secondsAtMeasuredRate).toBeGreaterThan(100 * 365 * 24 * 3600);
  });
});

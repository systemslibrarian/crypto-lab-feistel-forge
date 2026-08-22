import { describe, expect, it } from 'vitest';
import {
  complementKeepsParity,
  complementSearch,
  complementWitness,
  keyFromIndex,
  naiveSearch,
  raceSearches,
} from './complement';
import { encryptBlock } from '../des/des';
import { bytesEqual, complementBytes, parseHex, randomBytes, toHex } from '../des/bytes';
import { fixParity, hasOddParity, parityErrors } from '../des/weakKeys';

const hex = (s: string): Uint8Array => {
  const parsed = parseHex(s);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
};

describe('the complementation property', () => {
  it('holds on the classic FIPS example', () => {
    const witness = complementWitness(hex('133457799bbcdff1'), hex('0123456789abcdef'));
    expect(witness.holds).toBe(true);
    // Both sides are computed by different routes; assert they agree AND that
    // the value is not trivially the plain ciphertext.
    expect(toHex(witness.ciphertextOfComplements)).toBe(toHex(witness.complementOfCiphertext));
    expect(toHex(witness.ciphertextOfComplements)).not.toBe(toHex(witness.ciphertext));
  });

  it('holds on 300 random key/plaintext pairs', () => {
    for (let i = 0; i < 300; i++) {
      expect(complementWitness(randomBytes(8), randomBytes(8)).holds).toBe(true);
    }
  });

  it('holds on the CAVP variable-plaintext key too', () => {
    for (let bit = 0; bit < 64; bit++) {
      const block = new Uint8Array(8);
      block[bit >> 3] = 0x80 >> (bit & 7);
      expect(complementWitness(hex('0101010101010101'), block).holds).toBe(true);
    }
  });

  it('the complement of a valid key is itself a valid key', () => {
    for (let i = 0; i < 100; i++) {
      const key = fixParity(randomBytes(8));
      expect(parityErrors(key)).toEqual([]);
      const complement = complementBytes(key);
      expect(parityErrors(complement)).toEqual([]);
      for (let b = 0; b < 8; b++) expect(hasOddParity(complement[b])).toBe(true);
      expect(complementKeepsParity(key)).toBe(true);
    }
  });
});

describe('the reduced search space', () => {
  it('keyFromIndex is injective and produces parity-valid keys', () => {
    const base = fixParity(randomBytes(8));
    const seen = new Set<string>();
    for (let i = 0; i < 4096; i++) {
      const key = keyFromIndex(i, 12, base);
      expect(parityErrors(key)).toEqual([]);
      seen.add(toHex(key));
    }
    expect(seen.size).toBe(4096);
  });

  it('leaves every bit outside the swept range at its base value', () => {
    const base = fixParity(randomBytes(8));
    const key = keyFromIndex(0, 7, base);
    // Seven swept bits occupy the top seven bits of byte 0 only.
    for (let b = 1; b < 8; b++) expect(key[b]).toBe(base[b]);
  });

  it('refuses a width outside 1..56 rather than silently clamping', () => {
    expect(() => keyFromIndex(0, 0, new Uint8Array(8))).toThrow(/1\.\.56/);
    expect(() => keyFromIndex(0, 57, new Uint8Array(8))).toThrow(/1\.\.56/);
  });
});

describe('the two searches', () => {
  const base = hex('0101010101010101');
  const plaintext = hex('0123456789abcdef');

  it('plain brute force finds a key that IS in the swept space', () => {
    const target = keyFromIndex(200, 10, base);
    const c1 = encryptBlock(target, plaintext);
    const found = naiveSearch(plaintext, c1, 10, base);
    expect(found.foundIndex).toBe(200);
    expect(found.encryptions).toBe(201);
    expect(found.keysCovered).toBe(201);
    expect(found.key && bytesEqual(found.key, target)).toBe(true);
  });

  it('plain brute force MISSES a key that is the complement of one in the space', () => {
    const target = complementBytes(keyFromIndex(200, 10, base));
    const c1 = encryptBlock(target, plaintext);
    const found = naiveSearch(plaintext, c1, 10, base);
    expect(found.foundIndex).toBe(-1);
    expect(found.key).toBeNull();
    expect(found.encryptions).toBe(1024);
  });

  it('the complementation search finds it, and says it found the complement', () => {
    const race = raceSearches(200, true, 10, base, plaintext);
    expect(race.plain.foundIndex).toBe(-1);
    expect(race.clever.foundIndex).toBe(200);
    expect(race.clever.foundAsComplement).toBe(true);
    expect(race.clever.key && bytesEqual(race.clever.key, race.targetKey)).toBe(true);
  });

  /**
   * The halving, MEASURED. Each search reports the encryptions it actually
   * performed and the keys those encryptions covered; the ratio is the property
   * and it is computed from the counters rather than asserted as a constant.
   */
  it('covers exactly twice as many keys per encryption', () => {
    const race = raceSearches(300, false, 10, base, plaintext);
    expect(race.plainKeysPerEncryption).toBe(1);
    expect(race.cleverKeysPerEncryption).toBe(2);
    expect(race.clever.keysCovered).toBe(2 * race.plain.keysCovered);
    expect(race.clever.encryptions).toBe(race.plain.encryptions);
  });

  it('an exhausted complementation search still covers twice the space', () => {
    const c1 = encryptBlock(randomBytes(8), plaintext);
    const c2 = encryptBlock(randomBytes(8), plaintext);
    const result = complementSearch(plaintext, c1, c2, 8, base);
    expect(result.foundIndex).toBe(-1);
    expect(result.encryptions).toBe(256);
    expect(result.keysCovered).toBe(512);
  });

  it('the race reports the key it actually planted', () => {
    for (const half of [false, true]) {
      const race = raceSearches(17, half, 8, base, plaintext);
      expect(race.targetWasComplement).toBe(half);
      const expected = half ? complementBytes(keyFromIndex(17, 8, base)) : keyFromIndex(17, 8, base);
      expect(bytesEqual(race.targetKey, expected)).toBe(true);
    }
  });
});

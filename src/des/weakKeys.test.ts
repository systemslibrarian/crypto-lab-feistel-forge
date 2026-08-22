/**
 * The key-policy tests.
 *
 * The weak and semi-weak key lists are the kind of table that gets copied
 * between projects and rots. Here they are PROVED by running the cipher: a
 * weak key must satisfy E_K(E_K(P)) = P for every P tried, and a semi-weak
 * pair must satisfy E_K2(E_K1(P)) = P. A wrong entry fails these tests rather
 * than sitting quietly in a list.
 */
import { describe, expect, it } from 'vitest';
import { encryptBlock, keySchedule } from './des';
import { bytesEqual, parseHex, randomBytes, toHex } from './bytes';
import {
  doubleEncrypt,
  fixParity,
  hasOddParity,
  inspectKey,
  parityErrors,
  parseKeyStrict,
  SEMI_WEAK_KEYS,
  SEMI_WEAK_PAIRS,
  weakKeyReason,
  WEAK_KEYS,
} from './weakKeys';

const hex = (s: string): Uint8Array => {
  const parsed = parseHex(s);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
};

describe('parity', () => {
  it('recognises odd parity byte by byte', () => {
    expect(hasOddParity(0x01)).toBe(true);
    expect(hasOddParity(0x00)).toBe(false);
    expect(hasOddParity(0xfe)).toBe(true);
    expect(hasOddParity(0xff)).toBe(false);
  });

  it('fixParity touches only the low bit, never a key bit', () => {
    for (let i = 0; i < 200; i++) {
      const key = randomBytes(8);
      const fixed = fixParity(key);
      for (let b = 0; b < 8; b++) {
        expect(fixed[b] & 0xfe).toBe(key[b] & 0xfe);
        expect(hasOddParity(fixed[b])).toBe(true);
      }
    }
  });

  it('names every byte whose parity is wrong', () => {
    const key = hex('0000010101010101');
    expect(parityErrors(key)).toEqual([0, 1]);
    expect(parityErrors(hex('0101010101010101'))).toEqual([]);
  });
});

describe('weak keys, proved by execution', () => {
  it.each(WEAK_KEYS)('%s is an involution: E_K(E_K(P)) = P', (keyHex) => {
    const key = hex(keyHex);
    for (let i = 0; i < 60; i++) {
      const block = randomBytes(8);
      const { twice } = doubleEncrypt(key, block);
      expect(toHex(twice)).toBe(toHex(block));
    }
  });

  it.each(WEAK_KEYS)('%s generates one subkey sixteen times', (keyHex) => {
    const subkeys = keySchedule(hex(keyHex)).subkeys.map(toHex);
    expect(new Set(subkeys).size).toBe(1);
  });

  it.each(WEAK_KEYS)('%s has C0 and D0 each all-zeros or all-ones', (keyHex) => {
    const report = inspectKey(hex(keyHex));
    expect([0, 0x0fffffff]).toContain(report.c0);
    expect([0, 0x0fffffff]).toContain(report.d0);
    expect(report.keyClass).toBe('weak');
    expect(weakKeyReason(hex(keyHex))).toMatch(/all (zeros|ones).*all (zeros|ones)/);
  });

  it('every weak key carries valid odd parity, so parity does not screen them out', () => {
    for (const keyHex of WEAK_KEYS) expect(parityErrors(hex(keyHex))).toEqual([]);
  });

  it('a randomly chosen key is not weak', () => {
    for (let i = 0; i < 50; i++) expect(inspectKey(fixParity(randomBytes(8))).keyClass).toBe('ok');
  });

  it('weakKeyReason returns null for a key that is not weak', () => {
    expect(weakKeyReason(hex('133457799bbcdff1'))).toBeNull();
  });
});

describe('semi-weak keys, proved by execution', () => {
  it.each(SEMI_WEAK_PAIRS)('E_%s then E_%s is the identity', (a, b) => {
    const ka = hex(a);
    const kb = hex(b);
    for (let i = 0; i < 40; i++) {
      const block = randomBytes(8);
      expect(toHex(encryptBlock(kb, encryptBlock(ka, block)))).toBe(toHex(block));
      expect(toHex(encryptBlock(ka, encryptBlock(kb, block)))).toBe(toHex(block));
    }
  });

  it.each(SEMI_WEAK_PAIRS)('%s / %s each generate exactly two distinct subkeys', (a, b) => {
    expect(new Set(keySchedule(hex(a)).subkeys.map(toHex)).size).toBe(2);
    expect(new Set(keySchedule(hex(b)).subkeys.map(toHex)).size).toBe(2);
  });

  it('the twelve semi-weak keys are distinct and none of them is weak', () => {
    expect(new Set(SEMI_WEAK_KEYS).size).toBe(12);
    for (const k of SEMI_WEAK_KEYS) expect(WEAK_KEYS).not.toContain(k);
  });

  it('inspectKey names the partner of a semi-weak key', () => {
    for (const [a, b] of SEMI_WEAK_PAIRS) {
      expect(inspectKey(hex(a)).partner).toBe(b);
      expect(inspectKey(hex(b)).partner).toBe(a);
    }
  });
});

describe('strict key parsing', () => {
  it('accepts a healthy key', () => {
    const parsed = parseKeyStrict('133457799bbcdff1');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value.keyClass).toBe('ok');
  });

  it('refuses bad parity with PARITY_INVALID and names every offending byte', () => {
    // Bytes 1 and 3 are 0x00 (even parity); the rest are 0x01 (odd, fine).
    const parsed = parseKeyStrict('0001000101010101');
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.error.code).toBe('PARITY_INVALID');
      expect(parsed.error.message).toContain('byte 1');
      expect(parsed.error.message).toContain('byte 3');
      expect(parsed.error.message).not.toContain('byte 2');
      expect(parsed.error.detail).toBe('0,2');
    }
  });

  it('names a single offending byte in the singular', () => {
    const parsed = parseKeyStrict('0101010101010100');
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.error.message).toContain('byte 8 does not');
  });

  it('refuses each weak key with WEAK_KEY', () => {
    for (const k of WEAK_KEYS) {
      const parsed = parseKeyStrict(k);
      expect(parsed.ok).toBe(false);
      if (!parsed.ok) expect(parsed.error.code).toBe('WEAK_KEY');
    }
  });

  it('refuses each semi-weak key with SEMI_WEAK_KEY and names its partner', () => {
    for (const [a, b] of SEMI_WEAK_PAIRS) {
      const parsed = parseKeyStrict(a);
      expect(parsed.ok).toBe(false);
      if (!parsed.ok) {
        expect(parsed.error.code).toBe('SEMI_WEAK_KEY');
        expect(parsed.error.message).toContain(b);
      }
    }
  });

  it('refuses a wrong-length key with KEY_LENGTH_INVALID', () => {
    const parsed = parseKeyStrict('13345779');
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.error.code).toBe('KEY_LENGTH_INVALID');
  });

  it('refuses non-hex with INPUT_NOT_HEX rather than skipping the character', () => {
    const parsed = parseKeyStrict('133457799bbcdfzz');
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.error.code).toBe('INPUT_NOT_HEX');
  });

  it('allowWeak lets the deliberately-broken exhibit through, and nothing else does', () => {
    expect(parseKeyStrict(WEAK_KEYS[0]).ok).toBe(false);
    expect(parseKeyStrict(WEAK_KEYS[0], { allowWeak: true }).ok).toBe(true);
    // allowWeak must NOT relax the parity check.
    expect(parseKeyStrict('0001010101010101', { allowWeak: true }).ok).toBe(false);
  });

  it('tolerates 0x prefixes and separators without tolerating bad digits', () => {
    const spaced = parseKeyStrict('0x13 34 57 79 9b bc df f1');
    expect(spaced.ok).toBe(true);
    if (spaced.ok) expect(bytesEqual(spaced.value.key, hex('133457799bbcdff1'))).toBe(true);
    expect(parseKeyStrict('13 34 57 79 9b bc df g1').ok).toBe(false);
  });
});

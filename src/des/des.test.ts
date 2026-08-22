/**
 * Structural tests for the cipher core.
 *
 * The CAVP vectors in `vectors.test.ts` already prove the whole function is
 * right. What is tested here is the STRUCTURE those vectors cannot see —
 * properties the exhibits assert on screen, so a broken one would put a false
 * claim in front of a learner even while the cipher stayed correct.
 */
import { describe, expect, it } from 'vitest';
import {
  bitsToInt,
  decryptBlock,
  encryptBlock,
  getBit,
  keySchedule,
  permute,
  rotateLeft28,
  setBit,
  traceBlock,
} from './des';
import { E, FP, IP, P, PC1, PC2, SBOX, SHIFTS } from './tables';
import { bytesEqual, parseHex, randomBytes, toHex, xorBytes } from './bytes';

const hex = (s: string): Uint8Array => {
  const parsed = parseHex(s);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
};

describe('bit plumbing', () => {
  it('numbers bit 1 as the most significant bit of the first byte', () => {
    const b = hex('8000000000000000');
    expect(getBit(b, 1)).toBe(1);
    expect(getBit(b, 2)).toBe(0);
    expect(getBit(hex('0000000000000001'), 64)).toBe(1);
  });

  it('setBit and getBit are inverse over every position', () => {
    const b = new Uint8Array(8);
    for (let n = 1; n <= 64; n++) {
      setBit(b, n, 1);
      expect(getBit(b, n)).toBe(1);
      setBit(b, n, 0);
      expect(getBit(b, n)).toBe(0);
    }
    expect(toHex(b)).toBe('0000000000000000');
  });

  it('rotateLeft28 stays inside 28 bits and cycles in 28 steps', () => {
    let v = 0x0a5c3e7;
    const start = v;
    for (let i = 0; i < 28; i++) {
      v = rotateLeft28(v, 1);
      expect(v).toBeLessThanOrEqual(0x0fffffff);
    }
    expect(v).toBe(start);
  });
});

describe('the tables themselves', () => {
  it('IP and FP are inverse permutations of each other', () => {
    for (let i = 0; i < 64; i++) expect(IP[FP[i] - 1]).toBe(i + 1);
    for (let i = 0; i < 64; i++) expect(FP[IP[i] - 1]).toBe(i + 1);
  });

  it('IP, FP, P, PC-1 and PC-2 select each source bit the expected number of times', () => {
    const census = (table: readonly number[], sourceBits: number): number[] => {
      const counts = new Array<number>(sourceBits).fill(0);
      for (const n of table) counts[n - 1]++;
      return counts;
    };
    // IP, FP and P are bijections: every source bit used exactly once.
    expect(census(IP, 64).every((c) => c === 1)).toBe(true);
    expect(census(FP, 64).every((c) => c === 1)).toBe(true);
    expect(census(P, 32).every((c) => c === 1)).toBe(true);
    // PC-1 selects 56 of 64: the eight parity bits are dropped.
    const pc1 = census(PC1, 64);
    expect(pc1.filter((c) => c === 1)).toHaveLength(56);
    expect(pc1.map((c, i) => (c === 0 ? i + 1 : 0)).filter(Boolean)).toEqual([8, 16, 24, 32, 40, 48, 56, 64]);
    // PC-2 selects 48 of 56.
    expect(census(PC2, 56).filter((c) => c === 1)).toHaveLength(48);
    // E repeats sixteen bits and drops none.
    const e = census(E, 32);
    expect(e.filter((c) => c === 2)).toHaveLength(16);
    expect(e.filter((c) => c === 1)).toHaveLength(16);
  });

  it('the sixteen key-schedule shifts sum to 28, so C16 = C0', () => {
    expect(SHIFTS.reduce((a, b) => a + b, 0)).toBe(28);
  });

  it('every S-box is a 4x16 table whose rows are permutations of 0..15', () => {
    expect(SBOX).toHaveLength(8);
    for (const box of SBOX) {
      expect(box).toHaveLength(64);
      for (let row = 0; row < 4; row++) {
        const values = box.slice(row * 16, row * 16 + 16);
        expect([...values].sort((a, b) => a - b)).toEqual([...Array(16).keys()]);
      }
    }
  });
});

describe('the key schedule', () => {
  it('produces sixteen 48-bit subkeys', () => {
    const schedule = keySchedule(hex('133457799bbcdff1'));
    expect(schedule.subkeys).toHaveLength(16);
    for (const k of schedule.subkeys) expect(k).toHaveLength(6);
  });

  it('returns C and D to their starting values after sixteen rounds', () => {
    const key = randomBytes(8);
    const schedule = keySchedule(key);
    const cd0 = permute(key, PC1);
    expect(schedule.c[15]).toBe(bitsToInt(cd0, 1, 28));
    expect(schedule.d[15]).toBe(bitsToInt(cd0, 29, 28));
  });

  it('ignores the parity bits entirely: flipping them changes no subkey', () => {
    const key = randomBytes(8);
    const flipped = new Uint8Array(key);
    for (let i = 0; i < 8; i++) flipped[i] ^= 1;
    const a = keySchedule(key).subkeys.map(toHex).join('');
    const b = keySchedule(flipped).subkeys.map(toHex).join('');
    expect(b).toBe(a);
    // ...and therefore the ciphertext is identical too, which is exactly why
    // parity is a transmission check and not a strength check.
    const block = randomBytes(8);
    expect(toHex(encryptBlock(flipped, block))).toBe(toHex(encryptBlock(key, block)));
  });
});

describe('encrypt / decrypt', () => {
  it('round-trips over 200 random key/block pairs', () => {
    for (let i = 0; i < 200; i++) {
      const key = randomBytes(8);
      const block = randomBytes(8);
      expect(toHex(decryptBlock(key, encryptBlock(key, block)))).toBe(toHex(block));
    }
  });

  it('is a permutation: 512 distinct blocks give 512 distinct ciphertexts', () => {
    const key = hex('133457799bbcdff1');
    const seen = new Set<string>();
    for (let i = 0; i < 512; i++) {
      const block = new Uint8Array(8);
      block[6] = (i >> 8) & 0xff;
      block[7] = i & 0xff;
      seen.add(toHex(encryptBlock(key, block)));
    }
    expect(seen.size).toBe(512);
  });

  it('rejects a key or block of the wrong length rather than padding it', () => {
    expect(() => encryptBlock(new Uint8Array(7), new Uint8Array(8))).toThrow(/8 bytes/);
    expect(() => encryptBlock(new Uint8Array(8), new Uint8Array(9))).toThrow(/8 bytes/);
    expect(() => decryptBlock(new Uint8Array(8), new Uint8Array(4))).toThrow(/8 bytes/);
  });

  /** Avalanche: one flipped plaintext bit should move about half the output. */
  it('diffuses a single input bit across the block', () => {
    const key = randomBytes(8);
    const block = randomBytes(8);
    const base = encryptBlock(key, block);
    let total = 0;
    for (let bit = 1; bit <= 64; bit++) {
      const flipped = new Uint8Array(block);
      setBit(flipped, bit, getBit(block, bit) ^ 1);
      const diff = xorBytes(base, encryptBlock(key, flipped));
      let ones = 0;
      for (let n = 1; n <= 64; n++) ones += getBit(diff, n);
      total += ones;
      // No single-bit change may leave the output untouched or invert it whole.
      expect(ones).toBeGreaterThan(10);
      expect(ones).toBeLessThan(54);
    }
    expect(total / 64).toBeGreaterThan(28);
    expect(total / 64).toBeLessThan(36);
  });
});

describe('the trace', () => {
  it('records sixteen rounds whose output matches the plain encryption', () => {
    const key = hex('133457799bbcdff1');
    const block = hex('0123456789abcdef');
    const trace = traceBlock(key, block, 'encrypt');
    expect(trace.rounds).toHaveLength(16);
    expect(toHex(trace.output)).toBe(toHex(encryptBlock(key, block)));
  });

  it('the recorded halves chain: L(i) = R(i-1) and R(i) = L(i-1) XOR f', () => {
    const trace = traceBlock(randomBytes(8), randomBytes(8), 'encrypt');
    for (const r of trace.rounds) {
      expect(bytesEqual(r.leftOut, r.rightIn)).toBe(true);
      expect(bytesEqual(r.rightOut, xorBytes(r.leftIn, r.fOut))).toBe(true);
    }
    for (let i = 1; i < trace.rounds.length; i++) {
      expect(bytesEqual(trace.rounds[i].leftIn, trace.rounds[i - 1].leftOut)).toBe(true);
      expect(bytesEqual(trace.rounds[i].rightIn, trace.rounds[i - 1].rightOut)).toBe(true);
    }
  });

  it('the preoutput is R16 || L16 — the final swap really happens', () => {
    const trace = traceBlock(randomBytes(8), randomBytes(8), 'encrypt');
    const last = trace.rounds[15];
    expect(toHex(trace.preoutput.subarray(0, 4))).toBe(toHex(last.rightOut));
    expect(toHex(trace.preoutput.subarray(4, 8))).toBe(toHex(last.leftOut));
  });

  it('the decrypt trace consumes exactly the encrypt subkeys, reversed', () => {
    const key = randomBytes(8);
    const forward = traceBlock(key, randomBytes(8), 'encrypt').subkeys.map(toHex);
    const backward = traceBlock(key, randomBytes(8), 'decrypt').subkeys.map(toHex);
    expect(backward).toEqual([...forward].reverse());
  });

  it('the recorded S-box row/column selection reproduces the recorded output', () => {
    const trace = traceBlock(randomBytes(8), randomBytes(8), 'encrypt');
    for (const r of trace.rounds) {
      for (let box = 0; box < 8; box++) {
        const six = r.sboxIn[box];
        expect(r.sboxRow[box]).toBe(((six >> 4) & 0b10) | (six & 1));
        expect(r.sboxCol[box]).toBe((six >> 1) & 0b1111);
        expect(r.sboxOut[box]).toBe(SBOX[box][r.sboxRow[box] * 16 + r.sboxCol[box]]);
      }
    }
  });
});

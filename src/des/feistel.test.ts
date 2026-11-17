/**
 * The headline claim, as a test.
 *
 *     A Feistel network inverts no matter what F is.
 *
 * Every round function in `ROUND_FUNCTIONS` is exercised, including the ones
 * chosen to be as destructive as possible, and every one round-trips. The
 * exhibit shows this interactively; this file is what keeps the exhibit honest.
 */
import { describe, expect, it } from 'vitest';
import {
  desSubkeys,
  measureImage,
  ROUND_FUNCTIONS,
  roundFunctionById,
  runFeistel,
  runFeistelReversed,
  sboxCensus,
} from './feistel';
import { encryptBlock, permute } from './des';
import { FP, IP } from './tables';
import { bytesEqual, randomBytes, toHex } from './bytes';
import { fixParity } from './weakKeys';

const key = (): Uint8Array => fixParity(randomBytes(8));

describe('invertibility does not depend on F', () => {
  it.each(ROUND_FUNCTIONS.map((f) => [f.id, f] as const))(
    'F = %s: the reversed schedule undoes the forward run',
    (_id, f) => {
      for (let trial = 0; trial < 30; trial++) {
        const subkeys = desSubkeys(key());
        const block = randomBytes(8);
        const forward = runFeistel(block, subkeys, f);
        const back = runFeistelReversed(forward.output, subkeys, f);
        expect(toHex(back.output)).toBe(toHex(block));
      }
    }
  );

  it.each(ROUND_FUNCTIONS.map((f) => [f.id, f] as const))(
    'F = %s: it inverts at every round count from 1 to 16',
    (_id, f) => {
      const subkeys = desSubkeys(key());
      const block = randomBytes(8);
      for (let rounds = 1; rounds <= 16; rounds++) {
        const used = subkeys.slice(0, rounds);
        const forward = runFeistel(block, used, f);
        const back = runFeistelReversed(forward.output, used, f);
        expect(toHex(back.output)).toBe(toHex(block));
      }
    }
  );

  it.each(ROUND_FUNCTIONS.map((f) => [f.id, f] as const))(
    'F = %s: the network is a permutation over 256 distinct inputs',
    (_id, f) => {
      const subkeys = desSubkeys(key());
      const seen = new Set<string>();
      for (let i = 0; i < 256; i++) {
        const block = new Uint8Array(8);
        block[7] = i;
        seen.add(toHex(runFeistel(block, subkeys, f).output));
      }
      expect(seen.size).toBe(256);
    }
  );

  it('a single round is undone by a single reversed round', () => {
    const f = roundFunctionById('zero');
    const subkeys = desSubkeys(key()).slice(0, 1);
    const block = randomBytes(8);
    const forward = runFeistel(block, subkeys, f);
    expect(toHex(runFeistelReversed(forward.output, subkeys, f).output)).toBe(toHex(block));
  });
});

describe('the round functions really are destructive', () => {
  it('F = 0 maps every input to the same output', () => {
    const m = measureImage(roundFunctionById('zero'), new Uint8Array(6), 12);
    expect(m.outputs).toBe(1);
    expect(m.collapseRatio).toBe(m.inputs);
  });

  it('F = R AND K collapses wherever the subkey has a zero bit', () => {
    const subkey = new Uint8Array([0x0f, 0x0f, 0x0f, 0x0f, 0x00, 0x00]);
    const m = measureImage(roundFunctionById('and'), subkey, 16);
    expect(m.outputs).toBeLessThan(m.inputs);
    expect(m.collapseRatio).toBeGreaterThan(1);
  });

  it('F = (R AND 0x0F0F0F0F) XOR K is exactly 256-to-1 over a 16-bit sweep', () => {
    // The sweep varies the low 16 bits of R; the mask keeps 4 of every 8, so 8
    // of those 16 bits survive: 65536 inputs onto 256 outputs.
    const m = measureImage(roundFunctionById('nibble'), new Uint8Array(6), 16);
    expect(m.inputs).toBe(65536);
    expect(m.outputs).toBe(256);
    expect(m.collapseRatio).toBe(256);
  });

  it('F = (R AND 0x0F0F0F0F) XOR K is exactly 2^16-to-1 over the whole half block', () => {
    // The 16-bit sweep above sees only a slice. The ratio over the full 32-bit
    // half block is settled by exhaustion in two halves, with no sampling: the
    // 16 bits the mask DISCARDS cannot change the output, and the 16 bits it
    // KEEPS always do — so every output has exactly 2^16 preimages.
    const f = roundFunctionById('nibble');
    const subkey = new Uint8Array([0x3c, 0xa5, 0x5a, 0xc3, 0x00, 0x00]);
    const pack = (b: Uint8Array): number => ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    const nibbles = (v: number, shift: number): Uint8Array =>
      new Uint8Array([
        ((v >>> 12) & 0xf) << shift,
        ((v >>> 8) & 0xf) << shift,
        ((v >>> 4) & 0xf) << shift,
        (v & 0xf) << shift,
      ]);

    // Sweep all 2^16 settings of the discarded high nibbles, kept bits fixed.
    const kept = [0x0a, 0x05, 0x0c, 0x03];
    const collapsed = new Set<number>();
    for (let v = 0; v < 65536; v++) {
      const right = nibbles(v, 4);
      for (let i = 0; i < 4; i++) right[i] |= kept[i];
      collapsed.add(pack(f.apply(right, subkey)));
    }
    expect(collapsed.size).toBe(1);

    // Sweep all 2^16 settings of the kept low nibbles, discarded bits fixed.
    const distinct = new Set<number>();
    for (let v = 0; v < 65536; v++) {
      const right = nibbles(v, 0);
      for (let i = 0; i < 4; i++) right[i] |= 0xf0;
      distinct.add(pack(f.apply(right, subkey)));
    }
    expect(distinct.size).toBe(2 ** 16);
    expect(2 ** 32 / distinct.size).toBe(2 ** 16);
  });

  it("DES's own f collapses too, but only slightly on a narrow slice", () => {
    // The honest result: a few hundred inputs collide, not most of them. This
    // measurement is evidence that f is NOT injective, and nothing more. It is
    // not a narrow view of a 2^16-to-1 collapse — f has no such collapse, as
    // the wide sweep below shows. 2^16-to-1 is the S-box layer's ratio on its
    // own 48-bit domain, which the S-box census settles by exhaustion.
    const m = measureImage(roundFunctionById('des'), desSubkeys(key())[0], 14);
    expect(m.outputs).toBeLessThan(m.inputs);
    expect(m.outputs).toBeGreaterThan(0.9 * m.inputs);
    expect(m.collapseRatio).toBeGreaterThan(1);
  });

  it("DES's own f is nowhere near 2^16-to-1 on its 32-bit half", () => {
    // The UI note for DES's f used to read "Already 2^16-to-1 by itself". It is
    // not: 2^16-to-1 is what the eight S-boxes do to their own 48-bit input
    // (2^48 -> 2^32). f is handed 32 bits, E is injective and the subkey XOR is
    // a bijection, so f only ever visits 2^32 of those 2^48 points.
    //
    // measureImage() pins the top two bytes of R to zero, so it cannot see this;
    // sweep all four bytes here instead.
    const subkey = desSubkeys(key())[0];
    const f = roundFunctionById('des');
    const pack = (b: Uint8Array): number => ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    const inputs = 2 ** 22;
    const seen = new Set<number>();
    const right = new Uint8Array(4);
    for (let v = 0; v < inputs; v++) {
      right[0] = (v >>> 24) & 0xff;
      right[1] = (v >>> 16) & 0xff;
      right[2] = (v >>> 8) & 0xff;
      right[3] = v & 0xff;
      seen.add(pack(f.apply(right, subkey)));
    }
    const ratio = inputs / seen.size;
    // Real collisions — f is not injective …
    expect(seen.size).toBeLessThan(inputs);
    // … but about one input per output, not 65 536 of them.
    expect(ratio).toBeLessThan(1.5);
    expect(ratio).toBeGreaterThan(1);
    expect(ratio).toBeLessThan(2 ** 16 / 1000);
  });
});

describe('the S-box census — where f loses its information', () => {
  it.each([0, 1, 2, 3, 4, 5, 6, 7])('S%i maps 64 inputs onto 16 outputs, four preimages each', (box) => {
    const census = sboxCensus(box);
    expect(census.inputs).toBe(64);
    expect(census.distinctOutputs).toBe(16);
    expect(census.uniform).toBe(true);
    expect(census.preimageCounts.every((c) => c === 4)).toBe(true);
  });

  it('all eight boxes together collapse 2^16 expanded inputs onto each output', () => {
    const total = [0, 1, 2, 3, 4, 5, 6, 7].reduce((product, box) => product * sboxCensus(box).preimageCounts[0], 1);
    expect(total).toBe(2 ** 16);
  });
});

describe('DES is exactly FP(feistel(IP(block)))', () => {
  it('the generic network with F = DES-f reproduces the real cipher', () => {
    for (let i = 0; i < 40; i++) {
      const k = key();
      const block = randomBytes(8);
      const run = runFeistel(permute(block, IP), desSubkeys(k), roundFunctionById('des'));
      expect(bytesEqual(permute(run.output, FP), encryptBlock(k, block))).toBe(true);
    }
  });

  it('the recorded steps chain correctly', () => {
    const run = runFeistel(randomBytes(8), desSubkeys(key()), roundFunctionById('des'));
    expect(run.steps).toHaveLength(16);
    for (let i = 1; i < run.steps.length; i++) {
      expect(bytesEqual(run.steps[i].leftIn, run.steps[i - 1].leftOut)).toBe(true);
      expect(bytesEqual(run.steps[i].rightIn, run.steps[i - 1].rightOut)).toBe(true);
    }
  });

  it('without the final swap the reversed run does NOT land on the plaintext', () => {
    // The swap is load-bearing, not decoration. Asserted so the exhibit's claim
    // that it is what makes the identical circuit decrypt is a measurement.
    const subkeys = desSubkeys(key());
    const block = randomBytes(8);
    const f = roundFunctionById('des');
    const forward = runFeistel(block, subkeys, f, false);
    const back = runFeistelReversed(forward.output, subkeys, f, false);
    expect(toHex(back.output)).not.toBe(toHex(block));
  });
});

describe('the catalogue', () => {
  it('exposes exactly one genuine DES round function', () => {
    expect(ROUND_FUNCTIONS.filter((f) => f.isDes)).toHaveLength(1);
  });

  it('refuses an unknown id rather than falling back to a default', () => {
    expect(() => roundFunctionById('nope')).toThrow(/unknown round function/);
  });

  it('rejects a block of the wrong size', () => {
    expect(() => runFeistel(new Uint8Array(7), desSubkeys(key()), ROUND_FUNCTIONS[0])).toThrow(/8 bytes/);
  });
});

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

  it('F = (R AND 0x0F0F0F0F) XOR K is exactly 16-to-1 over a 16-bit sweep', () => {
    // The sweep varies the low 16 bits of R; the mask keeps 4 of every 8, so 8
    // of those 16 bits survive: 65536 inputs onto 256 outputs.
    const m = measureImage(roundFunctionById('nibble'), new Uint8Array(6), 16);
    expect(m.inputs).toBe(65536);
    expect(m.outputs).toBe(256);
    expect(m.collapseRatio).toBe(256);
  });

  it("DES's own f collapses too, but only slightly on a narrow slice", () => {
    // The honest result, and the reason the S-box census exists. Sweeping 14
    // bits of R moves only some of the eight S-boxes, so most of the 2^16-to-1
    // collapse f really has is out of view: a few hundred inputs collide, not
    // most of them. This measurement is therefore evidence that f is NOT
    // injective — and NOT a measurement of how much f discards.
    const m = measureImage(roundFunctionById('des'), desSubkeys(key())[0], 14);
    expect(m.outputs).toBeLessThan(m.inputs);
    expect(m.outputs).toBeGreaterThan(0.9 * m.inputs);
    expect(m.collapseRatio).toBeGreaterThan(1);
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

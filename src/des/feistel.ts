/**
 * The Feistel network itself, with a swappable round function.
 *
 * This module exists to make ONE claim checkable by hand:
 *
 *     A Feistel network is invertible no matter what F is.
 *
 * That is the property the whole construction is built on, and it is invisible
 * in an SPN, where every layer must itself be a bijection or the cipher cannot
 * be decrypted at all. In a Feistel round
 *
 *     L(i) = R(i-1)
 *     R(i) = L(i-1) XOR F(R(i-1), K(i))
 *
 * the inverse never asks anything of F. Given (L(i), R(i)) you already hold
 * R(i-1) — it is L(i) — so you can recompute the SAME F(R(i-1), K(i)) and XOR it
 * back off R(i) to recover L(i-1). F is evaluated forwards in both directions.
 * It is never inverted, so it does not need to be invertible, and it does not
 * need to be injective, and it does not even need to be interesting.
 *
 * `ROUND_FUNCTIONS` therefore includes deliberately destructive choices — one
 * that returns a constant, one that ANDs away most of its input — alongside
 * DES's genuine f. `measureImage()` MEASURES how much each one collapses rather
 * than asserting it, and the network round-trips under all of them.
 *
 * The network here is DES's core WITHOUT IP and FP: DES is exactly
 * FP( feistel( IP(block) ) ) with F = DES's f and the 16 real subkeys, which is
 * asserted as a test rather than as a comment (`feistel.test.ts`).
 */
import { keySchedule, roundFunction } from './des';
import { SBOX } from './tables';
import { xorBytes } from './bytes';

/** A pluggable round function: 32 bits and a 48-bit subkey in, 32 bits out. */
export interface FeistelRoundFunction {
  readonly id: string;
  readonly name: string;
  /** One line naming what this F does to its input, for the UI. */
  readonly note: string;
  /** True only for DES's genuine round function. */
  readonly isDes: boolean;
  readonly apply: (right: Uint8Array, subkey: Uint8Array) => Uint8Array;
}

function and32(right: Uint8Array, subkey: Uint8Array): Uint8Array {
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) out[i] = right[i] & subkey[i];
  return out;
}

function nibble32(right: Uint8Array, subkey: Uint8Array): Uint8Array {
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) out[i] = (right[i] & 0x0f) ^ subkey[i];
  return out;
}

/**
 * The round functions the exhibit offers.
 *
 * `zero` is the extreme case and the one worth sitting with: F ignores both its
 * input and the key, so it carries no information at all, and the network is
 * still a permutation. It is of course a terrible cipher — with F constant the
 * round is just a swap and an XOR with a fixed value — but it is an INVERTIBLE
 * terrible cipher, which is the point being made.
 */
export const ROUND_FUNCTIONS: readonly FeistelRoundFunction[] = [
  {
    id: 'des',
    name: "DES's own f",
    note: 'Expand to 48 bits, mix the subkey, eight S-boxes, permute. Already 2^16-to-1 by itself.',
    isDes: true,
    apply: roundFunction,
  },
  {
    id: 'zero',
    name: 'F(R, K) = 0',
    note: 'Throws away everything. Every input maps to the same output — as non-invertible as a function gets.',
    isDes: false,
    apply: () => new Uint8Array(4),
  },
  {
    id: 'and',
    name: 'F(R, K) = R AND K',
    note: 'Clears every bit where the subkey is 0. Wherever the key has a zero, two inputs collide.',
    isDes: false,
    apply: and32,
  },
  {
    id: 'nibble',
    name: 'F(R, K) = (R AND 0x0F0F0F0F) XOR K',
    note: 'Keeps four bits of every byte and discards the other four. Exactly 16-to-1.',
    isDes: false,
    apply: nibble32,
  },
];

export function roundFunctionById(id: string): FeistelRoundFunction {
  const found = ROUND_FUNCTIONS.find((f) => f.id === id);
  if (!found) throw new RangeError(`unknown round function: ${id}`);
  return found;
}

/** One recorded round of the generic network. */
export interface FeistelStep {
  readonly round: number;
  readonly leftIn: Uint8Array;
  readonly rightIn: Uint8Array;
  readonly subkey: Uint8Array;
  readonly fOut: Uint8Array;
  readonly leftOut: Uint8Array;
  readonly rightOut: Uint8Array;
}

export interface FeistelRun {
  readonly input: Uint8Array;
  readonly output: Uint8Array;
  readonly steps: readonly FeistelStep[];
  readonly finalSwap: boolean;
}

/**
 * Run the network over a 64-bit block, recording each round.
 *
 * `finalSwap` reproduces DES's last exchange of halves. With it on, running the
 * same function again with the subkeys reversed is the inverse; with it off,
 * the inverse is the reversed-key run plus a swap at each end. The exhibit
 * leaves it on so the "identical circuit, reversed schedule" claim is literal.
 */
export function runFeistel(
  block: Uint8Array,
  subkeys: readonly Uint8Array[],
  f: FeistelRoundFunction,
  finalSwap = true
): FeistelRun {
  if (block.length !== 8) throw new RangeError(`Feistel block must be 8 bytes, got ${block.length}`);
  let left: Uint8Array = block.slice(0, 4);
  let right: Uint8Array = block.slice(4, 8);
  const steps: FeistelStep[] = [];
  for (let i = 0; i < subkeys.length; i++) {
    const fOut = f.apply(right, subkeys[i]);
    const rightOut = xorBytes(left, fOut);
    steps.push({
      round: i + 1,
      leftIn: left,
      rightIn: right,
      subkey: subkeys[i],
      fOut,
      leftOut: right,
      rightOut,
    });
    left = right;
    right = rightOut;
  }
  const output = new Uint8Array(8);
  if (finalSwap) {
    output.set(right, 0);
    output.set(left, 4);
  } else {
    output.set(left, 0);
    output.set(right, 4);
  }
  return { input: block, output, steps, finalSwap };
}

/** The same circuit with the schedule reversed — which is what "decrypt" means here. */
export function runFeistelReversed(
  block: Uint8Array,
  subkeys: readonly Uint8Array[],
  f: FeistelRoundFunction,
  finalSwap = true
): FeistelRun {
  return runFeistel(block, [...subkeys].reverse(), f, finalSwap);
}

/** The 16 real DES subkeys, for driving the generic network with DES's schedule. */
export function desSubkeys(key: Uint8Array): readonly Uint8Array[] {
  return keySchedule(key).subkeys;
}

export interface ImageMeasurement {
  /** How many distinct inputs were tried. */
  readonly inputs: number;
  /** How many distinct outputs came back. */
  readonly outputs: number;
  /** inputs / outputs, rounded — the average number of inputs sharing an output. */
  readonly collapseRatio: number;
  /** Which 32-bit inputs were swept: the low `bits` bits, the rest held at 0. */
  readonly bits: number;
}

/**
 * MEASURE how many inputs a round function collapses together.
 *
 * Sweeps the low `bits` bits of R (holding the rest at zero), applies F, and
 * counts distinct outputs. This is a measurement over a subspace, not a proof
 * about the whole domain — but a function that maps 65,536 inputs onto 256
 * outputs is demonstrably not injective, and that is all the exhibit claims.
 *
 * For DES's own f the count comes back a little BELOW the input count — real
 * collisions, a few hundred of them, far more than chance would give. That is
 * evidence f is not injective, but it is not a measurement of how much f
 * discards: a narrow sweep of R moves only some of the eight S-boxes, so most
 * of the collapse is out of view. `sboxCensus` is where that one is shown
 * properly, by exhaustion rather than by sampling.
 */
export function measureImage(f: FeistelRoundFunction, subkey: Uint8Array, bits = 16): ImageMeasurement {
  const inputs = 2 ** bits;
  const seen = new Set<number>();
  const right = new Uint8Array(4);
  for (let v = 0; v < inputs; v++) {
    right[0] = 0;
    right[1] = 0;
    right[2] = (v >>> 8) & 0xff;
    right[3] = v & 0xff;
    const out = f.apply(right, subkey);
    seen.add(((out[0] << 24) | (out[1] << 16) | (out[2] << 8) | out[3]) >>> 0);
  }
  return {
    inputs,
    outputs: seen.size,
    collapseRatio: inputs / seen.size,
    bits,
  };
}

export interface SboxCensus {
  readonly box: number;
  /** 64 — every 6-bit input. */
  readonly inputs: number;
  /** 16 — every 4-bit output value is reachable. */
  readonly distinctOutputs: number;
  /** How many 6-bit inputs map to each 4-bit output. Every entry is 4. */
  readonly preimageCounts: readonly number[];
  /** True when every output has the same number of preimages. */
  readonly uniform: boolean;
}

/**
 * Count preimages for one DES S-box, by exhaustion over all 64 inputs.
 *
 * This is the honest demonstration that DES's f is not invertible, and it needs
 * no sampling: each box is a 6-to-4-bit map, every 4-bit value occurs exactly
 * once in each of the four rows, so every output has exactly four preimages.
 * Eight boxes, four preimages each: f collapses 4^8 = 2^16 expanded inputs onto
 * every 32-bit output it produces.
 */
export function sboxCensus(box: number): SboxCensus {
  const counts = new Array<number>(16).fill(0);
  for (let six = 0; six < 64; six++) {
    const row = ((six >> 4) & 0b10) | (six & 1);
    const col = (six >> 1) & 0b1111;
    counts[SBOX[box][row * 16 + col]]++;
  }
  const distinct = counts.filter((c) => c > 0).length;
  return {
    box,
    inputs: 64,
    distinctOutputs: distinct,
    preimageCounts: counts,
    uniform: counts.every((c) => c === counts[0]),
  };
}

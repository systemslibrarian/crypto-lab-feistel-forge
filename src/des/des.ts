/**
 * DES — the full 16-round Data Encryption Standard, hand-rolled.
 *
 * This is the real cipher: FIPS 46-3's IP/FP, the PC-1/PC-2 key schedule with
 * its rotation table, the expansion E, all eight S-boxes and the permutation P.
 * Nothing is stubbed, approximated or borrowed from a library — WebCrypto does
 * not implement DES and OpenSSL 3 moved it into the legacy provider, so the
 * only way to run it in a browser is to write it, and writing it is also the
 * point: every intermediate value in `traceBlock` is a real one.
 *
 * ## Why this is written at the bit level
 *
 * A fast DES packs the S-boxes and P into eight precomputed 64-entry tables and
 * the permutations into shift/mask ladders. That implementation is three times
 * quicker and completely opaque. Here the permutations are literal walks over
 * the tables in `tables.ts`, so a reader can hold FIPS 46-3 beside the source
 * and check it line by line. `benchmark()` measures what that costs; the
 * meet-in-the-middle exhibit is sized against the measurement.
 *
 * ## Bit numbering
 *
 * The standard numbers bits 1..64 left to right, bit 1 being the most
 * significant bit of the first byte. `getBit`/`setBit` are the only two
 * functions that know this, so every table stays readable as printed.
 *
 * NOT PRODUCTION CRYPTOGRAPHY. DES is broken; this implementation is also not
 * constant-time (the S-box lookups are data-dependent array indexing) and makes
 * no attempt to be. It is a teaching artifact.
 */
import { E, FP, IP, P, PC1, PC2, SBOX, SHIFTS } from './tables';
import type { BlockTrace, RoundTrace } from './types';

/** Read bit `n` (1-based, MSB-first) out of a byte array. */
export function getBit(src: Uint8Array, n: number): number {
  return (src[(n - 1) >> 3] >> (7 - ((n - 1) & 7))) & 1;
}

/** Write bit `n` (1-based, MSB-first) into a byte array. */
export function setBit(dst: Uint8Array, n: number, value: number): void {
  const index = (n - 1) >> 3;
  const mask = 1 << (7 - ((n - 1) & 7));
  if (value) dst[index] |= mask;
  else dst[index] &= ~mask;
}

/**
 * Apply a permutation table: output bit i takes the value of input bit
 * `table[i]`. This one function is IP, FP, E, P, PC-1 and PC-2.
 */
export function permute(src: Uint8Array, table: readonly number[]): Uint8Array {
  const out = new Uint8Array((table.length + 7) >> 3);
  for (let i = 0; i < table.length; i++) {
    if (getBit(src, table[i])) out[i >> 3] |= 1 << (7 - (i & 7));
  }
  return out;
}

/** Read `count` bits starting at bit `from` (1-based) as an unsigned integer. */
export function bitsToInt(src: Uint8Array, from: number, count: number): number {
  let value = 0;
  for (let i = 0; i < count; i++) value = value * 2 + getBit(src, from + i);
  return value;
}

/** Write the low `count` bits of `value` into `dst` starting at bit `from`. */
function intToBits(value: number, count: number, dst: Uint8Array, from: number): void {
  for (let i = 0; i < count; i++) setBit(dst, from + i, (value >>> (count - 1 - i)) & 1);
}

/** Rotate a 28-bit register left. The key schedule's C and D are exactly this wide. */
export function rotateLeft28(value: number, by: number): number {
  return ((value << by) | (value >>> (28 - by))) & 0x0fffffff;
}

function xorInto(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** The key schedule, kept alongside its C and D registers for the schedule view. */
export interface KeySchedule {
  /** K1..K16, each 48 bits in six bytes. */
  readonly subkeys: readonly Uint8Array[];
  /** C1..C16 as 28-bit integers. */
  readonly c: readonly number[];
  /** D1..D16 as 28-bit integers. */
  readonly d: readonly number[];
}

/**
 * Derive K1..K16 from a 64-bit key.
 *
 * PC-1 drops the eight parity bits and splits the remaining 56 into C0 and D0.
 * Each round rotates both halves left by `SHIFTS[i]` and PC-2 compresses the
 * pair to a 48-bit subkey. The shifts sum to 28, so C16 = C0 and D16 = D0: the
 * schedule is a cycle. That single fact is why decryption is the same circuit
 * with the subkeys replayed backwards, and why the weak keys in `weakKeys.ts`
 * exist at all.
 */
export function keySchedule(key: Uint8Array): KeySchedule {
  if (key.length !== 8) throw new RangeError(`DES key must be 8 bytes, got ${key.length}`);
  const cd0 = permute(key, PC1);
  let c = bitsToInt(cd0, 1, 28);
  let d = bitsToInt(cd0, 29, 28);
  const subkeys: Uint8Array[] = [];
  const cs: number[] = [];
  const ds: number[] = [];
  for (let round = 0; round < 16; round++) {
    c = rotateLeft28(c, SHIFTS[round]);
    d = rotateLeft28(d, SHIFTS[round]);
    cs.push(c);
    ds.push(d);
    const cd = new Uint8Array(7);
    intToBits(c, 28, cd, 1);
    intToBits(d, 28, cd, 29);
    subkeys.push(permute(cd, PC2));
  }
  return { subkeys, c: cs, d: ds };
}

/**
 * f(R, K) — the DES round function.
 *
 * Expand R to 48 bits, mix in the subkey, run the eight S-boxes, permute the
 * 32 bits that come out. It is emphatically NOT a bijection: each S-box maps 6
 * bits to 4, so f discards half the information in its own input. The Feistel
 * structure never inverts it, which is why that does not matter — see
 * `feistel.ts`, where you can replace f with something even more destructive
 * and the network still round-trips.
 */
export function roundFunction(right: Uint8Array, subkey: Uint8Array): Uint8Array {
  const expanded = permute(right, E);
  const mixed = xorInto(expanded, subkey);
  const substituted = new Uint8Array(4);
  for (let box = 0; box < 8; box++) {
    const six = bitsToInt(mixed, box * 6 + 1, 6);
    const row = ((six >> 4) & 0b10) | (six & 1);
    const col = (six >> 1) & 0b1111;
    const value = SBOX[box][row * 16 + col];
    if ((box & 1) === 0) substituted[box >> 1] = value << 4;
    else substituted[box >> 1] |= value;
  }
  return permute(substituted, P);
}

function coreBlock(block: Uint8Array, subkeys: readonly Uint8Array[]): Uint8Array {
  const afterIP = permute(block, IP);
  let left = afterIP.subarray(0, 4);
  let right = afterIP.subarray(4, 8);
  for (let round = 0; round < 16; round++) {
    const next = xorInto(left, roundFunction(right, subkeys[round]));
    left = right;
    right = next;
  }
  // The 32-bit halves are swapped once more before FP. That final swap is what
  // makes the identical circuit decrypt: without it the network would end one
  // half out of phase and running it backwards would not land on the plaintext.
  const preoutput = new Uint8Array(8);
  preoutput.set(right, 0);
  preoutput.set(left, 4);
  return permute(preoutput, FP);
}

/** Encrypt one 64-bit block with the real 16-round DES. */
export function encryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  if (block.length !== 8) throw new RangeError(`DES block must be 8 bytes, got ${block.length}`);
  return coreBlock(block, keySchedule(key).subkeys);
}

/**
 * Decrypt one 64-bit block.
 *
 * Note what this function does NOT contain: an inverse round, an inverse
 * S-box, an inverse f. It calls the same `coreBlock` as encryption, with the
 * same subkeys, in the opposite order. That is the whole of DES decryption.
 */
export function decryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  if (block.length !== 8) throw new RangeError(`DES block must be 8 bytes, got ${block.length}`);
  return coreBlock(block, [...keySchedule(key).subkeys].reverse());
}

/**
 * Encrypt or decrypt one block, recording every intermediate value.
 *
 * The round exhibit renders straight out of this: nothing on screen is
 * recomputed by the UI, and nothing is a paraphrase of what the cipher did.
 */
export function traceBlock(
  key: Uint8Array,
  block: Uint8Array,
  direction: 'encrypt' | 'decrypt'
): BlockTrace {
  const schedule = keySchedule(key);
  const ordered = direction === 'encrypt' ? schedule.subkeys : [...schedule.subkeys].reverse();
  const afterIP = permute(block, IP);
  // Annotated rather than inferred: `slice()` narrows to `Uint8Array<ArrayBuffer>`,
  // and the values assigned back in the loop come from helpers declared as the
  // wider `Uint8Array`. Widening here keeps the loop assignable.
  let left: Uint8Array = afterIP.slice(0, 4);
  let right: Uint8Array = afterIP.slice(4, 8);
  const rounds: RoundTrace[] = [];

  for (let round = 0; round < 16; round++) {
    const subkey = ordered[round];
    const expanded = permute(right, E);
    const mixed = xorInto(expanded, subkey);
    const sboxIn: number[] = [];
    const sboxRow: number[] = [];
    const sboxCol: number[] = [];
    const sboxOut: number[] = [];
    const substituted = new Uint8Array(4);
    for (let box = 0; box < 8; box++) {
      const six = bitsToInt(mixed, box * 6 + 1, 6);
      const row = ((six >> 4) & 0b10) | (six & 1);
      const col = (six >> 1) & 0b1111;
      const value = SBOX[box][row * 16 + col];
      sboxIn.push(six);
      sboxRow.push(row);
      sboxCol.push(col);
      sboxOut.push(value);
      if ((box & 1) === 0) substituted[box >> 1] = value << 4;
      else substituted[box >> 1] |= value;
    }
    const fOut = permute(substituted, P);
    const rightOut = xorInto(left, fOut);
    rounds.push({
      round: round + 1,
      leftIn: left,
      rightIn: right,
      subkey,
      expanded,
      mixed,
      sboxIn,
      sboxRow,
      sboxCol,
      sboxOut,
      substituted,
      fOut,
      leftOut: right,
      rightOut,
    });
    left = right;
    right = rightOut;
  }

  const preoutput = new Uint8Array(8);
  preoutput.set(right, 0);
  preoutput.set(left, 4);
  return {
    direction,
    key,
    input: block,
    afterIP,
    rounds,
    preoutput,
    output: permute(preoutput, FP),
    subkeys: ordered,
    cRegisters: schedule.c,
    dRegisters: schedule.d,
  };
}

/**
 * Blocks per second, measured rather than guessed.
 *
 * The meet-in-the-middle exhibit needs to promise a wall-clock time before it
 * starts, and the only honest source for that promise is a measurement on the
 * machine it is about to run on.
 */
export function benchmark(blocks = 2000): { blocks: number; ms: number; blocksPerSecond: number } {
  const key = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);
  const block = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
  const started = performance.now();
  let acc: Uint8Array = block;
  for (let i = 0; i < blocks; i++) acc = encryptBlock(key, acc);
  const ms = performance.now() - started;
  // Keep the loop from being optimised away without pretending the value matters.
  if (acc.length !== 8) throw new Error('unreachable');
  return { blocks, ms, blocksPerSecond: ms > 0 ? (blocks * 1000) / ms : Infinity };
}

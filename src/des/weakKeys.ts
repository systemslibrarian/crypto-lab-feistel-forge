/**
 * Key policy: parity, weak keys, semi-weak keys.
 *
 * A DES key is 64 bits of which only 56 are key. The other eight — bit 8 of
 * every byte — are odd parity over the seven bits above them, and PC-1 drops
 * them before the schedule ever sees them. Two consequences a learner should
 * meet in that order:
 *
 *  1. Parity is a TRANSMISSION check, not a strength check. Getting it wrong
 *     does not weaken the key; it means the key you loaded is not the key
 *     somebody sent. This lab refuses it (PARITY_INVALID) because a library
 *     that silently accepts it is lying about having checked anything.
 *
 *  2. Four keys make the cipher its own inverse. `WEAK_KEYS` lists them, and
 *     `weakKeys.test.ts` PROVES each one by running the cipher rather than by
 *     trusting this comment: for a weak key, E_K(E_K(P)) = P for every P.
 *
 * The mechanism is the key schedule's cycle. PC-1 splits the key into C0 and
 * D0; the sixteen rotations sum to 28, so the registers come back to where they
 * started. When C0 and D0 are each all-zeros or all-ones, rotation does nothing
 * at all — every round gets the SAME subkey, the reversed schedule is identical
 * to the forward one, and encryption and decryption become the same operation.
 */
import { bitsToInt, encryptBlock, permute } from './des';
import { PC1 } from './tables';
import { parseHex, toHex } from './bytes';
import type { Result } from './types';
import { fail, ok } from './types';

/**
 * The four DES weak keys, with correct odd parity.
 *
 * Listed here as hex because that is how they appear in the literature, and
 * verified by execution in the test suite so the list cannot rot into a wrong
 * comment. Their C0/D0 registers are (0, 0), (2^28-1, 2^28-1), (2^28-1, 0) and
 * (0, 2^28-1) respectively — `weakKeyReason` recomputes that for the UI, so a
 * wrong entry here would print a visibly wrong sentence rather than a lie.
 */
export const WEAK_KEYS: readonly string[] = [
  '0101010101010101',
  'fefefefefefefefe',
  'e0e0e0e0f1f1f1f1',
  '1f1f1f1f0e0e0e0e',
];

/**
 * The six semi-weak PAIRS. Each pair satisfies E_K2(E_K1(P)) = P: not a
 * self-inverse, but two keys that undo one another, which collapses a
 * two-key construction the same way.
 */
export const SEMI_WEAK_PAIRS: readonly (readonly [string, string])[] = [
  ['011f011f010e010e', '1f011f010e010e01'],
  ['01e001e001f101f1', 'e001e001f101f101'],
  ['01fe01fe01fe01fe', 'fe01fe01fe01fe01'],
  ['1fe01fe00ef10ef1', 'e01fe01ff10ef10e'],
  ['1ffe1ffe0efe0efe', 'fe1ffe1ffe0efe0e'],
  ['e0fee0fef1fef1fe', 'fee0fee0fef1fef1'],
];

/** Every semi-weak key, flattened. */
export const SEMI_WEAK_KEYS: readonly string[] = SEMI_WEAK_PAIRS.flat();

/** True when a byte carries odd parity — an odd number of set bits. */
export function hasOddParity(byte: number): boolean {
  let bits = 0;
  for (let i = 0; i < 8; i++) bits += (byte >> i) & 1;
  return bits % 2 === 1;
}

/** Set the low bit of a byte so the byte carries odd parity. */
export function fixParityByte(byte: number): number {
  return hasOddParity(byte) ? byte : byte ^ 1;
}

/** Repair every parity bit in a key, leaving all 56 key bits untouched. */
export function fixParity(key: Uint8Array): Uint8Array {
  const out = new Uint8Array(key.length);
  for (let i = 0; i < key.length; i++) out[i] = fixParityByte(key[i]);
  return out;
}

/** The indices of every byte whose parity bit is wrong. */
export function parityErrors(key: Uint8Array): number[] {
  const bad: number[] = [];
  for (let i = 0; i < key.length; i++) if (!hasOddParity(key[i])) bad.push(i);
  return bad;
}

export type KeyClass = 'ok' | 'weak' | 'semi-weak';

export interface KeyReport {
  readonly key: Uint8Array;
  readonly hex: string;
  readonly parityOk: boolean;
  readonly badParityBytes: readonly number[];
  readonly keyClass: KeyClass;
  /** C0 and D0 as 28-bit integers — what makes a weak key weak. */
  readonly c0: number;
  readonly d0: number;
  /** For a semi-weak key, its partner. */
  readonly partner?: string;
}

/** Everything the UI needs to say about a key, computed from the key itself. */
export function inspectKey(key: Uint8Array): KeyReport {
  const hex = toHex(key);
  const cd0 = permute(key, PC1);
  const c0 = bitsToInt(cd0, 1, 28);
  const d0 = bitsToInt(cd0, 29, 28);
  const bad = parityErrors(key);
  let keyClass: KeyClass = 'ok';
  let partner: string | undefined;
  if (WEAK_KEYS.includes(hex)) keyClass = 'weak';
  else {
    const pair = SEMI_WEAK_PAIRS.find((p) => p[0] === hex || p[1] === hex);
    if (pair) {
      keyClass = 'semi-weak';
      partner = pair[0] === hex ? pair[1] : pair[0];
    }
  }
  return { key, hex, parityOk: bad.length === 0, badParityBytes: bad, keyClass, c0, d0, partner };
}

/**
 * Human-readable statement of WHY a weak key is weak, recomputed from the key.
 *
 * Returns null for keys that are not weak. The wording names the register
 * values it actually read, so a wrong entry in `WEAK_KEYS` would produce a
 * visibly nonsensical sentence rather than a confident lie.
 */
export function weakKeyReason(key: Uint8Array): string | null {
  const report = inspectKey(key);
  if (report.keyClass !== 'weak') return null;
  const all1 = 0x0fffffff;
  const name = (v: number): string => (v === 0 ? 'all zeros' : v === all1 ? 'all ones' : `0x${v.toString(16)}`);
  return `C0 is ${name(report.c0)} and D0 is ${name(report.d0)}, so rotating them changes nothing: all sixteen subkeys are identical, the reversed schedule equals the forward one, and encryption is its own inverse.`;
}

/**
 * Parse a key from hex under this lab's policy.
 *
 * Fails closed on PARITY_INVALID and WEAK_KEY. `allowWeak` exists because the
 * weak-key exhibit has to be able to RUN one to show what it does — that is the
 * deliberately-vulnerable mode, and it is never the default: every call site
 * that passes it renders the alarm styling with it.
 */
export function parseKeyStrict(
  text: string,
  options: { allowWeak?: boolean; allowBadParity?: boolean } = {}
): Result<KeyReport> {
  const parsed = parseHex(text, 8);
  if (!parsed.ok) return parsed;
  const report = inspectKey(parsed.value);
  if (!report.parityOk && !options.allowBadParity) {
    const list = report.badParityBytes.map((i) => `byte ${i + 1}`).join(', ');
    return fail(
      'PARITY_INVALID',
      `DES keys carry odd parity in the low bit of every byte; ${list} ${report.badParityBytes.length === 1 ? 'does' : 'do'} not.`,
      report.badParityBytes.join(',')
    );
  }
  if (report.keyClass === 'weak' && !options.allowWeak) {
    return fail('WEAK_KEY', `${report.hex} is one of the four DES weak keys: encrypting twice returns the plaintext.`, report.hex);
  }
  if (report.keyClass === 'semi-weak' && !options.allowWeak) {
    return fail(
      'SEMI_WEAK_KEY',
      `${report.hex} is semi-weak: encrypting under ${report.partner} undoes it exactly.`,
      report.hex
    );
  }
  return ok(report);
}

/**
 * Demonstrate a weak key by running the cipher, not by asserting a property.
 *
 * Returns the double-encryption and whether it landed back on the plaintext.
 * The exhibit shows both, so a learner sees the claim tested rather than told.
 */
export function doubleEncrypt(key: Uint8Array, block: Uint8Array): { once: Uint8Array; twice: Uint8Array } {
  const once = encryptBlock(key, block);
  return { once, twice: encryptBlock(key, once) };
}

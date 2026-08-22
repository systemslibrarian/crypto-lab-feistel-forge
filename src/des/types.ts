/**
 * Shared types and the lab's failure codes.
 *
 * The three codes this lab exists to raise are WEAK_KEY, PARITY_INVALID and
 * BLOCK_SIZE_EXCEEDED. Each is a POLICY failure a real DES implementation is
 * supposed to raise and most historical ones did not:
 *
 *  - PARITY_INVALID      a DES key is 64 bits carrying 56 of key and 8 of odd
 *                        parity. A library that silently ignores the parity
 *                        byte accepts a key its operator believes was checked.
 *  - WEAK_KEY            four keys make encryption its own inverse. Feeding one
 *                        to a cipher is not a slow failure; it is an immediate
 *                        one, and the only safe response is to refuse.
 *  - BLOCK_SIZE_EXCEEDED the Sweet32 data limit. A 64-bit block cipher has a
 *                        birthday bound measured in blocks, not in years, and
 *                        it is the LIBRARY's job to stop at it. This is the
 *                        failure the demo's climax is about.
 *
 * The remaining codes are strict-parsing failures. They exist so that nothing
 * in this lab ever quietly coerces malformed input into something cipherable.
 */
export type FailureCode =
  // Policy failures — the three the lab is about.
  | 'WEAK_KEY'
  | 'PARITY_INVALID'
  | 'BLOCK_SIZE_EXCEEDED'
  // Strict parsing / structural failures.
  | 'SEMI_WEAK_KEY'
  | 'KEY_LENGTH_INVALID'
  | 'BLOCK_LENGTH_INVALID'
  | 'INPUT_NOT_HEX';

/** A refusal. Every failing path in this lab returns one rather than throwing. */
export interface Failure {
  readonly code: FailureCode;
  /** One sentence, aimed at a learner, naming what was wrong and why it matters. */
  readonly message: string;
  /** Where relevant: the offending byte index, block count, or key. */
  readonly detail?: string;
}

/** The result shape used everywhere a call can legitimately refuse. */
export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: Failure };

export const ok = <T>(value: T): Result<T> => ({ ok: true, value });
export const fail = <T>(code: FailureCode, message: string, detail?: string): Result<T> => ({
  ok: false,
  error: { code, message, detail },
});

/** One DES round, recorded in full so the UI never has to recompute anything. */
export interface RoundTrace {
  /** 1-based round number, as the standard numbers them. */
  readonly round: number;
  /** L(i-1) — the left half entering this round. */
  readonly leftIn: Uint8Array;
  /** R(i-1) — the right half entering this round, and f's input. */
  readonly rightIn: Uint8Array;
  /** K(i) — the 48-bit subkey for this round. */
  readonly subkey: Uint8Array;
  /** E(R) — 48 bits. */
  readonly expanded: Uint8Array;
  /** E(R) XOR K(i) — 48 bits, the eight 6-bit S-box inputs. */
  readonly mixed: Uint8Array;
  /** The eight 6-bit values fed to S1..S8. */
  readonly sboxIn: readonly number[];
  /** The row each S-box selected (outer two bits). */
  readonly sboxRow: readonly number[];
  /** The column each S-box selected (inner four bits). */
  readonly sboxCol: readonly number[];
  /** The eight 4-bit S-box outputs. */
  readonly sboxOut: readonly number[];
  /** The 32 bits leaving the S-boxes, before P. */
  readonly substituted: Uint8Array;
  /** f(R, K) — the S-box output after P. 32 bits. */
  readonly fOut: Uint8Array;
  /** L(i) = R(i-1). */
  readonly leftOut: Uint8Array;
  /** R(i) = L(i-1) XOR f(R(i-1), K(i)). */
  readonly rightOut: Uint8Array;
}

/** A whole block encryption or decryption, recorded end to end. */
export interface BlockTrace {
  readonly direction: 'encrypt' | 'decrypt';
  readonly key: Uint8Array;
  readonly input: Uint8Array;
  /** IP(input) — the block after the initial permutation. */
  readonly afterIP: Uint8Array;
  readonly rounds: readonly RoundTrace[];
  /** R16 || L16 — the 32-bit halves swapped once more before FP. */
  readonly preoutput: Uint8Array;
  readonly output: Uint8Array;
  /** The 16 subkeys in the order this direction consumed them. */
  readonly subkeys: readonly Uint8Array[];
  /** C1..C16 from the key schedule, for the schedule view. */
  readonly cRegisters: readonly number[];
  /** D1..D16 from the key schedule. */
  readonly dRegisters: readonly number[];
}

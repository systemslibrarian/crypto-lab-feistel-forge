/**
 * Byte and hex helpers.
 *
 * Parsing is strict on purpose: `parseHex` refuses anything that is not an even
 * run of hex digits, and refuses a length it was not asked for. Nothing in this
 * lab pads, truncates or coerces input into something cipherable — a demo that
 * silently fixes your key teaches you that keys are forgiving, which is the
 * opposite of true.
 */
import type { Result } from './types';
import { fail, ok } from './types';

const HEX = /^[0-9a-fA-F]*$/;

/** Format bytes as lowercase hex. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** Format bytes as spaced uppercase hex, one group per byte — the readable form. */
export function toSpacedHex(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) parts.push(bytes[i].toString(16).toUpperCase().padStart(2, '0'));
  return parts.join(' ');
}

/**
 * Parse hex, optionally requiring an exact byte length.
 *
 * Whitespace and a leading `0x` are stripped before validation, because a
 * learner pasting `0x01 23 45` has made no mistake worth refusing. Anything
 * else that is not a hex digit is a refusal, not a repair.
 */
export function parseHex(text: string, expectedBytes?: number): Result<Uint8Array> {
  const cleaned = text.trim().replace(/^0[xX]/, '').replace(/[\s_:-]/g, '');
  if (!HEX.test(cleaned)) {
    const bad = cleaned.split('').find((ch) => !/[0-9a-fA-F]/.test(ch));
    return fail('INPUT_NOT_HEX', `"${bad ?? '?'}" is not a hex digit.`, cleaned);
  }
  if (cleaned.length % 2 !== 0) {
    return fail('INPUT_NOT_HEX', `Hex needs an even number of digits; this has ${cleaned.length}.`, cleaned);
  }
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    const code = expectedBytes === 8 ? 'KEY_LENGTH_INVALID' : 'BLOCK_LENGTH_INVALID';
    return fail(
      code,
      `Expected ${expectedBytes} bytes (${expectedBytes * 2} hex digits); got ${bytes.length}.`,
      cleaned
    );
  }
  return ok(bytes);
}

/** XOR two equal-length byte arrays. */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new RangeError(`XOR length mismatch: ${a.length} vs ${b.length}`);
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** Bitwise complement — the operation the complementation exhibit is about. */
export function complementBytes(a: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = ~a[i] & 0xff;
  return out;
}

/** Constant-shape equality. Not constant-time: nothing here is a secret comparison. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** UTF-8 encode, for the CBC exhibit's message stream. */
export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Decode bytes as UTF-8, replacing anything unrepresentable. */
export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Render bytes as printable ASCII with a middle dot for everything else.
 *
 * The Sweet32 exhibit recovers a cookie block, and a learner needs to see it
 * become a word. Bytes outside 0x20..0x7e are shown as `·` rather than dropped,
 * so a partial recovery still reads as partial.
 */
export function toPrintable(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i] >= 0x20 && bytes[i] <= 0x7e ? String.fromCharCode(bytes[i]) : '·';
  }
  return out;
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Cryptographically random bytes. Used for demo keys and IVs only. */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

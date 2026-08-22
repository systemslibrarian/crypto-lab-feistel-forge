/**
 * The complementation property, and the one bit it costs the attacker.
 *
 *     DES( ~K, ~P ) = ~DES( K, P )
 *
 * Complement the key and the plaintext, and the ciphertext comes out
 * complemented too. It falls straight out of the structure: PC-1/PC-2 only
 * select bits, so complementing the key complements every subkey; E only
 * selects bits, so complementing R complements E(R); and complementing BOTH
 * sides of `E(R) XOR K` leaves the XOR unchanged — so every S-box sees exactly
 * the same six bits it would have seen. f is therefore identical, and the
 * complement propagates through the XOR chain untouched, round after round.
 *
 * ## Why an attacker cares
 *
 * A chosen-plaintext attacker asks for C1 = DES(K, P) and C2 = DES(K, ~P).
 * Now testing one candidate K' costs ONE encryption instead of two, because
 * that single result answers two questions:
 *
 *     X = DES(K', P);   X == C1  =>  K = K'
 *                       X == ~C2 =>  K = ~K'
 *
 * The second line is the property, rearranged: if K were ~K', then
 * DES(~K', ~P) would equal ~DES(K', P) = ~X, and DES(~K', ~P) is C2.
 *
 * So one encryption covers a key and its complement, and the search halves.
 * The Handbook of Applied Cryptography states the size of it exactly (§7.4.3):
 * the expected number of keys tried before success drops from 2^55 to 2^54.
 * One bit. It never grew into anything larger, and it needs CHOSEN plaintext,
 * so it is of no help in a known-plaintext search — but it is a real structural
 * weakness in a cipher that had no bits to spare.
 *
 * `raceSearches()` does not assert the halving. It runs both searches over the
 * same reduced keyspace and COUNTS the encryptions each one actually performed.
 */
import { encryptBlock } from '../des/des';
import { bytesEqual, complementBytes } from '../des/bytes';
import { fixParity } from '../des/weakKeys';

export interface ComplementWitness {
  readonly key: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly keyComplement: Uint8Array;
  readonly plaintextComplement: Uint8Array;
  /** DES(~K, ~P), computed by running the cipher. */
  readonly ciphertextOfComplements: Uint8Array;
  /** ~DES(K, P), computed by flipping bits. */
  readonly complementOfCiphertext: Uint8Array;
  /** Whether the two agree byte for byte. Compared, never assumed. */
  readonly holds: boolean;
}

/**
 * Compute both sides of the identity and compare them.
 *
 * Both sides are produced by different routes — one runs the cipher on
 * complemented inputs, the other complements the cipher's output — so an
 * agreement is evidence rather than a tautology.
 */
export function complementWitness(key: Uint8Array, plaintext: Uint8Array): ComplementWitness {
  const ciphertext = encryptBlock(key, plaintext);
  const keyComplement = complementBytes(key);
  const plaintextComplement = complementBytes(plaintext);
  const ciphertextOfComplements = encryptBlock(keyComplement, plaintextComplement);
  const complementOfCiphertext = complementBytes(ciphertext);
  return {
    key,
    plaintext,
    ciphertext,
    keyComplement,
    plaintextComplement,
    ciphertextOfComplements,
    complementOfCiphertext,
    holds: bytesEqual(ciphertextOfComplements, complementOfCiphertext),
  };
}

/**
 * Is ~K still a legal DES key?
 *
 * Yes, and the reason is worth one line: complementing a byte flips all eight
 * of its bits, an even number, so the byte's parity is unchanged. ~K therefore
 * carries valid odd parity exactly when K does. Returns whether both K and ~K
 * agree on parity validity — computed, so the claim is checked rather than
 * stated.
 */
export function complementKeepsParity(key: Uint8Array): boolean {
  const complement = complementBytes(key);
  const keyOk = bytesEqual(key, fixParity(key));
  const complementOk = bytesEqual(complement, fixParity(complement));
  return keyOk === complementOk;
}

/** A key drawn from a reduced search space, so a brute force finishes in a browser. */
export function keyFromIndex(index: number, bits: number, base: Uint8Array): Uint8Array {
  if (bits < 1 || bits > 56) throw new RangeError(`search width must be 1..56 bits, got ${bits}`);
  const out = new Uint8Array(base);
  for (let i = 0; i < bits; i++) {
    const bit = Math.floor(index / 2 ** (bits - 1 - i)) % 2;
    const byte = (i / 7) | 0;
    const mask = 1 << (7 - (i % 7));
    if (bit) out[byte] |= mask;
    else out[byte] &= ~mask;
  }
  return fixParity(out);
}

export interface SearchResult {
  readonly label: string;
  /** The index in the reduced space that was found, or -1. */
  readonly foundIndex: number;
  /** True when the match was found as the COMPLEMENT of a tested candidate. */
  readonly foundAsComplement: boolean;
  /** How many DES block encryptions the search actually performed. */
  readonly encryptions: number;
  /** How many candidate keys were ruled out, counting complements. */
  readonly keysCovered: number;
  readonly key: Uint8Array | null;
}

/**
 * Plain brute force: one encryption per candidate key, compared against C1.
 */
export function naiveSearch(
  plaintext: Uint8Array,
  c1: Uint8Array,
  bits: number,
  base: Uint8Array
): SearchResult {
  const span = 2 ** bits;
  let encryptions = 0;
  for (let i = 0; i < span; i++) {
    const candidate = keyFromIndex(i, bits, base);
    encryptions++;
    if (bytesEqual(encryptBlock(candidate, plaintext), c1)) {
      return {
        label: 'plain brute force',
        foundIndex: i,
        foundAsComplement: false,
        encryptions,
        keysCovered: i + 1,
        key: candidate,
      };
    }
  }
  return { label: 'plain brute force', foundIndex: -1, foundAsComplement: false, encryptions, keysCovered: span, key: null };
}

/**
 * The same search using the complementation property.
 *
 * Every candidate is tested once and answers for two keys, so the loop skips
 * any index whose complement it has already covered. `keysCovered` counts both.
 *
 * The bookkeeping detail that makes this honest: within a reduced index space,
 * complementing a key does NOT generally give another key in that space (the
 * fixed bits from `base` do not flip). So the search tracks complements as full
 * 8-byte keys, and reports a hit on ~K' by name rather than by index.
 */
export function complementSearch(
  plaintext: Uint8Array,
  c1: Uint8Array,
  c2: Uint8Array,
  bits: number,
  base: Uint8Array
): SearchResult {
  const span = 2 ** bits;
  const notC2 = complementBytes(c2);
  let encryptions = 0;
  for (let i = 0; i < span; i++) {
    const candidate = keyFromIndex(i, bits, base);
    encryptions++;
    const x = encryptBlock(candidate, plaintext);
    if (bytesEqual(x, c1)) {
      return {
        label: 'with complementation',
        foundIndex: i,
        foundAsComplement: false,
        encryptions,
        keysCovered: 2 * (i + 1),
        key: candidate,
      };
    }
    if (bytesEqual(x, notC2)) {
      return {
        label: 'with complementation',
        foundIndex: i,
        foundAsComplement: true,
        encryptions,
        keysCovered: 2 * (i + 1),
        key: complementBytes(candidate),
      };
    }
  }
  return {
    label: 'with complementation',
    foundIndex: -1,
    foundAsComplement: false,
    encryptions,
    keysCovered: 2 * span,
    key: null,
  };
}

export interface Race {
  readonly plain: SearchResult;
  readonly clever: SearchResult;
  /** Keys covered per encryption, measured for each search. */
  readonly plainKeysPerEncryption: number;
  readonly cleverKeysPerEncryption: number;
  readonly targetKey: Uint8Array;
  /** True when the target was placed in the complement half of the space. */
  readonly targetWasComplement: boolean;
}

/**
 * Run both searches against the same target and report what each cost.
 *
 * When the target key sits in the COMPLEMENT half — i.e. the real key is ~K'
 * for some K' in the swept space — the plain search never finds it at all and
 * the complementation search does. That is the halving seen from the other
 * side, and it is the more striking of the two demonstrations.
 */
export function raceSearches(
  targetIndex: number,
  useComplementHalf: boolean,
  bits: number,
  base: Uint8Array,
  plaintext: Uint8Array
): Race {
  const swept = keyFromIndex(targetIndex, bits, base);
  const targetKey = useComplementHalf ? complementBytes(swept) : swept;
  const c1 = encryptBlock(targetKey, plaintext);
  const c2 = encryptBlock(targetKey, complementBytes(plaintext));
  const plain = naiveSearch(plaintext, c1, bits, base);
  const clever = complementSearch(plaintext, c1, c2, bits, base);
  return {
    plain,
    clever,
    plainKeysPerEncryption: plain.keysCovered / plain.encryptions,
    cleverKeysPerEncryption: clever.keysCovered / clever.encryptions,
    targetKey,
    targetWasComplement: useComplementHalf,
  };
}

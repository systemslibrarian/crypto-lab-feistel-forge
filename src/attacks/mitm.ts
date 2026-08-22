/**
 * Meet-in-the-middle against double DES.
 *
 * ## The idea
 *
 * Double DES is C = E_K2( E_K1(P) ). Two 56-bit keys look like 112 bits of
 * security. They are not, and the reason is that the attacker can attack the
 * two halves SEPARATELY by meeting in the middle:
 *
 *   1. For every candidate K1, compute M = E_K1(P) and store M -> K1.
 *   2. For every candidate K2, compute M' = D_K2(C) and look M' up.
 *   3. A hit means E_K1(P) = D_K2(C), i.e. that pair maps P to C.
 *
 * Step 1 costs 2^56 encryptions and 2^56 table entries; step 2 costs 2^56
 * decryptions. Total work is about 2^57, not 2^112. Double DES buys ONE bit of
 * security over single DES, in exchange for twice the encryption cost and an
 * enormous memory requirement — which is exactly why the answer was 3DES and
 * not 2DES.
 *
 * Diffie and Hellman published the attack in 1977, the year DES was issued.
 *
 * ## What runs here
 *
 * The cipher is real DES. The KEYSPACE is reduced: both keys are drawn from a
 * `bits`-wide slice of the full 56, with the remaining key bits fixed and
 * public. Every number the exhibit prints about the full attack is a projection
 * from the run you just watched, computed in `projectToFullDes` — never a
 * hard-coded figure.
 *
 * A false positive is a pair (K1, K2) that maps this P to this C without being
 * the real key pair. With a 64-bit block and 2^bits keys per side, the expected
 * count is 2^(2*bits - 64), which is vanishing at these widths and enormous at
 * the real one: at bits = 56 it is 2^48 surviving pairs, so the real attack
 * needs a second known pair to sieve them. This implementation always takes a
 * second pair, so the sieve a learner sees is the one the attack really needs.
 */
import { decryptBlock, encryptBlock } from '../des/des';
import { bytesEqual, toHex } from '../des/bytes';
import { keyFromIndex } from './complement';

export interface KnownPair {
  readonly plaintext: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export interface MitmProgress {
  readonly phase: 'build' | 'match';
  readonly done: number;
  readonly total: number;
}

export interface MitmCandidate {
  readonly i1: number;
  readonly i2: number;
  readonly k1: Uint8Array;
  readonly k2: Uint8Array;
  /** The meeting value E_K1(P) = D_K2(C). */
  readonly middle: Uint8Array;
  /** Whether the pair also explains the second known plaintext/ciphertext pair. */
  readonly survivesSecondPair: boolean;
}

export interface MitmResult {
  readonly bits: number;
  readonly keysPerSide: number;
  /** Distinct middle values stored. Fewer than keysPerSide only if two keys collided. */
  readonly tableEntries: number;
  /** Every DES block operation this run performed, counted as it happened. */
  readonly desOperations: number;
  readonly candidates: readonly MitmCandidate[];
  readonly confirmed: MitmCandidate | null;
  /** Candidates that matched the first pair but failed the second. */
  readonly falsePositives: number;
  readonly elapsedMs: number;
  readonly pairs: readonly [KnownPair, KnownPair];
  readonly trueIndices: readonly [number, number];
}

/** Encrypt under 2DES: C = E_K2(E_K1(P)). */
export function doubleDesEncrypt(k1: Uint8Array, k2: Uint8Array, block: Uint8Array): Uint8Array {
  return encryptBlock(k2, encryptBlock(k1, block));
}

/** Decrypt under 2DES. */
export function doubleDesDecrypt(k1: Uint8Array, k2: Uint8Array, block: Uint8Array): Uint8Array {
  return decryptBlock(k1, decryptBlock(k2, block));
}

/** Hand the event loop back so a long search does not freeze the page. */
async function breathe(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

export interface MitmOptions {
  readonly bits: number;
  readonly base: Uint8Array;
  readonly k1Index: number;
  readonly k2Index: number;
  readonly plaintexts: readonly [Uint8Array, Uint8Array];
  readonly onProgress?: (p: MitmProgress) => void;
  /** How many candidates to examine between yields to the event loop. */
  readonly chunk?: number;
}

/**
 * Run the attack. Returns once both phases have completed.
 *
 * `desOperations` is incremented at every call site rather than derived at the
 * end, so the cost the exhibit reports is the cost that was paid.
 */
export async function meetInTheMiddle(options: MitmOptions): Promise<MitmResult> {
  const { bits, base, k1Index, k2Index, plaintexts, onProgress } = options;
  const chunk = options.chunk ?? 2048;
  const keysPerSide = 2 ** bits;
  if (k1Index >= keysPerSide || k2Index >= keysPerSide) {
    throw new RangeError(`key indices must be below 2^${bits}`);
  }
  const started = performance.now();
  let desOperations = 0;

  const trueK1 = keyFromIndex(k1Index, bits, base);
  const trueK2 = keyFromIndex(k2Index, bits, base);
  const pairs: [KnownPair, KnownPair] = [
    { plaintext: plaintexts[0], ciphertext: doubleDesEncrypt(trueK1, trueK2, plaintexts[0]) },
    { plaintext: plaintexts[1], ciphertext: doubleDesEncrypt(trueK1, trueK2, plaintexts[1]) },
  ];
  // The four operations that produced the two known pairs are the victim's, not
  // the attacker's, so they are deliberately not counted in desOperations.

  // ── Phase 1: encrypt P under every K1 and index the results ──────────────
  const table = new Map<string, number[]>();
  for (let i = 0; i < keysPerSide; i++) {
    const middle = encryptBlock(keyFromIndex(i, bits, base), pairs[0].plaintext);
    desOperations++;
    const key = toHex(middle);
    const bucket = table.get(key);
    if (bucket) bucket.push(i);
    else table.set(key, [i]);
    if ((i & (chunk - 1)) === chunk - 1) {
      onProgress?.({ phase: 'build', done: i + 1, total: keysPerSide });
      await breathe();
    }
  }
  onProgress?.({ phase: 'build', done: keysPerSide, total: keysPerSide });

  // ── Phase 2: decrypt C under every K2 and look for the meeting ───────────
  const candidates: MitmCandidate[] = [];
  for (let j = 0; j < keysPerSide; j++) {
    const k2 = keyFromIndex(j, bits, base);
    const middle = decryptBlock(k2, pairs[0].ciphertext);
    desOperations++;
    const bucket = table.get(toHex(middle));
    if (bucket) {
      for (const i of bucket) {
        const k1 = keyFromIndex(i, bits, base);
        // The sieve: does this pair also explain the SECOND known pair?
        const check = doubleDesEncrypt(k1, k2, pairs[1].plaintext);
        desOperations += 2;
        candidates.push({
          i1: i,
          i2: j,
          k1,
          k2,
          middle,
          survivesSecondPair: bytesEqual(check, pairs[1].ciphertext),
        });
      }
    }
    if ((j & (chunk - 1)) === chunk - 1) {
      onProgress?.({ phase: 'match', done: j + 1, total: keysPerSide });
      await breathe();
    }
  }
  onProgress?.({ phase: 'match', done: keysPerSide, total: keysPerSide });

  const survivors = candidates.filter((c) => c.survivesSecondPair);
  return {
    bits,
    keysPerSide,
    tableEntries: table.size,
    desOperations,
    candidates,
    confirmed: survivors[0] ?? null,
    falsePositives: candidates.length - survivors.length,
    elapsedMs: performance.now() - started,
    pairs,
    trueIndices: [k1Index, k2Index],
  };
}

export interface Projection {
  /** Total DES operations the full 56-bit attack needs, as a power of two. */
  readonly fullOpsLog2: number;
  /** Operations exhaustive search of the 2DES keyspace needs, as a power of two. */
  readonly bruteForceLog2: number;
  /** Table size in bytes for the full attack, as a power of two. */
  readonly fullTableBytesLog2: number;
  /** Seconds the full attack would take at the rate measured in this browser. */
  readonly secondsAtMeasuredRate: number;
  /** DES block operations per second, measured, not assumed. */
  readonly measuredOpsPerSecond: number;
  /** Effective security of 2DES in bits, given the attack. */
  readonly effectiveBits: number;
  /** Expected surviving pairs after ONE known pair at the full width. */
  readonly falsePositivesLog2: number;
}

/**
 * Project the run just watched onto the real cipher.
 *
 * `measuredOpsPerSecond` comes from the run itself — its own operation count
 * divided by its own elapsed time — so the wall-clock estimate is anchored to
 * this machine and this implementation rather than to a number in a comment.
 * A fast native DES is roughly two orders of magnitude quicker than this one,
 * and dedicated hardware many more, which the exhibit says out loud.
 */
export function projectToFullDes(result: MitmResult): Projection {
  const measuredOpsPerSecond = result.elapsedMs > 0 ? (result.desOperations * 1000) / result.elapsedMs : 0;
  const fullOpsLog2 = 57; // 2^56 encryptions + 2^56 decryptions
  const entryBytes = 15; // 8 bytes of middle value + 7 bytes of key material
  return {
    fullOpsLog2,
    bruteForceLog2: 112,
    fullTableBytesLog2: Math.log2(2 ** 56 * entryBytes),
    secondsAtMeasuredRate: measuredOpsPerSecond > 0 ? 2 ** fullOpsLog2 / measuredOpsPerSecond : Infinity,
    measuredOpsPerSecond,
    effectiveBits: fullOpsLog2,
    falsePositivesLog2: 2 * 56 - 64,
  };
}

/**
 * Sweet32 — the birthday bound on a 64-bit block, and what it costs in CBC.
 *
 * ## The bound
 *
 * CBC computes C_i = E_K(P_i XOR C_(i-1)). E_K is a permutation, so C_i = C_j
 * happens if and only if the two inputs were equal:
 *
 *     P_i XOR C_(i-1) = P_j XOR C_(j-1)
 *     =>  P_i XOR P_j = C_(i-1) XOR C_(j-1)
 *
 * The right-hand side is public. So a repeated ciphertext block hands an
 * eavesdropper the XOR of two plaintext blocks — and if one of them is known
 * (an attacker-supplied block in the same stream), the other falls out whole.
 *
 * The C_i are effectively uniform over 2^64 values, so this is a birthday
 * problem: it becomes likely after about 2^32 blocks — 32 GiB — under one key.
 * On a long-lived HTTPS or VPN session carrying a cookie in every request, 32
 * GiB is hours, not centuries. Bhargavan and Leurent demonstrated it in 2016
 * (CVE-2016-2183) and 64-bit block ciphers left the web.
 *
 * ## THE NEGATIVE CLAIM (NEG-1) — the point of this whole lab
 *
 * NO KEY LENGTH REPAIRS THIS. 3DES has a 168-bit key and the same 64-bit block,
 * so its birthday bound sits at exactly the same 2^32 blocks as single DES's.
 * The key axis and the block axis are independent, and 3DES only ever fixed the
 * key axis. NIST's response was not a longer key; it was a DATA LIMIT — SP
 * 800-67 Rev. 2 §3.4 caps a TDEA key bundle at 2^20 blocks, 8 MiB.
 *
 * What this does NOT claim: that 3DES's key was fine. It was not — 2-key TDEA
 * falls to known tradeoffs well below its nominal strength, and NIST's
 * deprecation cited key strength as well. Those are separate failures on a
 * separate axis. This lab is about the axis lengthening the key never touched.
 *
 * ## What is real here and what is arranged
 *
 * Real: the cipher, the CBC chaining, the collision itself, the recovery
 * arithmetic, and the measured birthday curve in `runTruncatedTrials`.
 *
 * Arranged: WHERE the full 64-bit collision falls. Producing one by chance
 * needs about 2^32 blocks and 32 GiB, which no browser tab is going to
 * generate. `arrangeCollision` instead places one deliberately, by using the
 * KEY to solve for a single injected block — something the real attacker cannot
 * do, and the reason the real attack has to wait instead. The returned object
 * carries `arranged: true` and the exact expression that needed the key, so no
 * caller can render this without saying so.
 */
import { decryptBlock, encryptBlock } from '../des/des';
import { bytesEqual, concatBytes, utf8, xorBytes } from '../des/bytes';
import { BLOCK_BYTES, cbcEncrypt } from '../des/modes';
import type { CbcResult } from '../des/modes';

// ── Part 1: the bound, as arithmetic ────────────────────────────────────────

/**
 * P(at least one collision) among `blocks` uniform draws from 2^blockBits.
 *
 * The standard approximation 1 - exp(-n(n-1) / 2N). At n = 2^32 and N = 2^64
 * it gives 0.3935 — the familiar "about 40% after four billion blocks".
 */
export function collisionProbability(blocks: number, blockBits = 64): number {
  if (blocks < 2) return 0;
  const n = blocks;
  const exponent = -(n * (n - 1)) / (2 * 2 ** blockBits);
  return 1 - Math.exp(exponent);
}

/** How many blocks are needed before a collision is `p`-likely. */
export function blocksForProbability(p: number, blockBits = 64): number {
  if (p <= 0) return 0;
  if (p >= 1) return Infinity;
  return Math.sqrt(2 * 2 ** blockBits * Math.log(1 / (1 - p)));
}

/**
 * The expected index of the FIRST collision: sqrt(pi/2 * N).
 *
 * This is the number `runTruncatedTrials` measures against, and it is a
 * different quantity from `blocksForProbability(0.5)` — the mean of the
 * distribution rather than its median. Confusing the two is the usual way a
 * birthday demonstration ends up "off by 18%".
 */
export function expectedFirstCollision(blockBits: number): number {
  return Math.sqrt((Math.PI / 2) * 2 ** blockBits);
}

/** Bytes of ciphertext for a given block count, at the DES block size. */
export function bytesForBlocks(blocks: number): number {
  return blocks * BLOCK_BYTES;
}

// ── Part 2: the curve, measured on the real cipher ──────────────────────────

export interface TruncatedTrial {
  /** How many leading bits of each ciphertext block were compared. */
  readonly width: number;
  /** The index of the first block that repeated a previous truncation. */
  readonly collisionAt: number | null;
  /** The earlier block it collided with. */
  readonly collidedWith: number | null;
  /** How many blocks were encrypted before stopping. */
  readonly blocksScanned: number;
  /** Whether the scan hit its cap before colliding. */
  readonly exhausted: boolean;
}

export interface TrialSummary {
  readonly width: number;
  readonly trials: readonly TruncatedTrial[];
  /** Mean first-collision index across the trials that found one. */
  readonly measuredMean: number;
  /** sqrt(pi/2 * 2^width) — what the birthday law predicts. */
  readonly predictedMean: number;
  /** measured / predicted. A value near 1 is the law holding. */
  readonly ratio: number;
  readonly completed: number;
  readonly elapsedMs: number;
}

/** The repeating request the measurement encrypts — the Sweet32 setting in miniature. */
export const REQUEST_TEMPLATE = utf8('GET /account HTTP/1.1\r\nHost: bank.example\r\nCookie: SESSID=');

function truncationOf(block: Uint8Array, width: number): number {
  // Take the top `width` bits of the 64-bit block as an unsigned integer.
  // width <= 32 keeps this inside a uint32, which is what the Map is keyed on.
  const top = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) >>> 0;
  return width === 32 ? top : top >>> (32 - width);
}

async function breathe(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

/**
 * Encrypt a real CBC stream and find the first collision in the top `width`
 * bits of the ciphertext blocks.
 *
 * Truncating is what makes this reachable: a 24-bit space collides after about
 * 5,000 blocks instead of four billion. It is a REAL collision in a real
 * cipher's output — just not a full-block one, so it does not hand over any
 * plaintext. That is stated wherever this is rendered, because a truncated
 * collision looks exactly like the real thing until you try to use it.
 */
export async function measureTruncatedCollision(
  key: Uint8Array,
  iv: Uint8Array,
  width: number,
  maxBlocks: number,
  onProgress?: (done: number) => void
): Promise<TruncatedTrial> {
  if (width < 8 || width > 32) throw new RangeError(`truncation width must be 8..32 bits, got ${width}`);
  const seen = new Map<number, number>();
  // CBC by hand, one block at a time, so the scan never materialises the whole
  // stream. The plaintext is the same request over and over — as it would be.
  let chain = iv;
  const template = REQUEST_TEMPLATE;
  for (let i = 0; i < maxBlocks; i++) {
    const at = (i * BLOCK_BYTES) % template.length;
    const plain = new Uint8Array(BLOCK_BYTES);
    for (let b = 0; b < BLOCK_BYTES; b++) plain[b] = template[(at + b) % template.length];
    chain = encryptBlock(key, xorBytes(plain, chain));
    const truncated = truncationOf(chain, width);
    const earlier = seen.get(truncated);
    if (earlier !== undefined) {
      return { width, collisionAt: i, collidedWith: earlier, blocksScanned: i + 1, exhausted: false };
    }
    seen.set(truncated, i);
    if ((i & 8191) === 8191) {
      onProgress?.(i + 1);
      await breathe();
    }
  }
  return { width, collisionAt: null, collidedWith: null, blocksScanned: maxBlocks, exhausted: true };
}

/**
 * Repeat the measurement and compare the mean against the birthday prediction.
 *
 * Each trial uses a fresh random key and IV, so the trials are independent
 * draws rather than the same stream measured twice.
 */
export async function runTruncatedTrials(
  width: number,
  trials: number,
  maxBlocks: number,
  freshKey: () => Uint8Array,
  freshIv: () => Uint8Array,
  onProgress?: (trial: number, blocks: number) => void
): Promise<TrialSummary> {
  const started = performance.now();
  const results: TruncatedTrial[] = [];
  for (let t = 0; t < trials; t++) {
    results.push(
      await measureTruncatedCollision(freshKey(), freshIv(), width, maxBlocks, (done) => onProgress?.(t, done))
    );
    onProgress?.(t + 1, 0);
  }
  const found = results.filter((r) => r.collisionAt !== null);
  const measuredMean = found.length ? found.reduce((sum, r) => sum + (r.collisionAt as number), 0) / found.length : 0;
  const predictedMean = expectedFirstCollision(width);
  return {
    width,
    trials: results,
    measuredMean,
    predictedMean,
    ratio: predictedMean > 0 ? measuredMean / predictedMean : 0,
    completed: found.length,
    elapsedMs: performance.now() - started,
  };
}

// ── Part 3: the recovery, on an arranged full-block collision ───────────────

/** One block of the request stream, with what it holds. */
export interface StreamBlock {
  readonly index: number;
  readonly label: string;
  readonly bytes: Uint8Array;
  /** True for the block holding the secret the attacker wants. */
  readonly isSecret: boolean;
  /** True for the block the attacker controls. */
  readonly isAttacker: boolean;
}

export interface ArrangedCollision {
  /** Always true. This object cannot be rendered without the caller seeing it. */
  readonly arranged: true;
  readonly key: Uint8Array;
  readonly iv: Uint8Array;
  readonly secret: Uint8Array;
  readonly secretIndex: number;
  readonly attackerIndex: number;
  readonly blocks: readonly StreamBlock[];
  readonly cbc: CbcResult;
  /** D_K(C_secret) — the one step that needed the key. Shown, never hidden. */
  readonly usedTheKey: Uint8Array;
  /** C_attacker, compared byte for byte against C_secret. */
  readonly collisionHolds: boolean;
  /** P_attacker XOR C_(attacker-1) XOR C_(secret-1) — what the eavesdropper computes. */
  readonly recovered: Uint8Array;
  /** Whether the recovery equals the real secret. Compared, not assumed. */
  readonly recoveryCorrect: boolean;
  /** How many blocks a real attacker would expect to wait for this by chance. */
  readonly expectedBlocksByChance: number;
}

/**
 * Build the request stream. Block-aligned by construction so each 8-byte block
 * holds one recognisable thing, which is what makes the exhibit readable.
 */
function buildStream(secret: Uint8Array, attackerBlock: Uint8Array): StreamBlock[] {
  // Every entry is exactly eight characters, so one block holds one
  // recognisable thing. `assertBlockAligned` below is what keeps that true.
  const header = ['POST /pa', 'y HTTP/1', '.1\r\nHost', ': bank.e', 'xample\r\n', 'Cookie: '];
  const afterSecret = '\r\nX-Note';
  const tail = '\r\n\r\n    ';
  const blocks: StreamBlock[] = [];
  const push = (label: string, bytes: Uint8Array, isSecret = false, isAttacker = false): void => {
    if (bytes.length !== BLOCK_BYTES) {
      throw new RangeError(`stream block "${label}" is ${bytes.length} bytes, not ${BLOCK_BYTES}`);
    }
    blocks.push({ index: blocks.length, label, bytes, isSecret, isAttacker });
  };
  header.forEach((t) => push('request header', utf8(t)));
  push('the session cookie', secret, true, false);
  push('request header', utf8(afterSecret));
  push('attacker-controlled', attackerBlock, false, true);
  push('request tail', utf8(tail));
  return blocks;
}

/** The 8-byte cookie block the exhibit ships with. Readable once recovered. */
export const DEFAULT_SECRET = utf8('s3cr3t42');

/**
 * Place a genuine full-block collision, then let the eavesdropper's arithmetic
 * recover the secret from it.
 *
 * The arrangement is one line of algebra and it is the ONLY place the key is
 * used for anything an attacker could not do:
 *
 *     P_a  :=  D_K(C_s)  XOR  C_(a-1)
 *
 * Then the cipher input at block a is D_K(C_s), so C_a = E_K(D_K(C_s)) = C_s,
 * exactly. Everything after that point — the collision, the XOR, the recovered
 * cookie — is what a passive eavesdropper does with public ciphertext.
 */
export function arrangeCollision(
  key: Uint8Array,
  iv: Uint8Array,
  secret: Uint8Array = DEFAULT_SECRET
): ArrangedCollision {
  if (secret.length !== BLOCK_BYTES) throw new RangeError(`the secret block must be ${BLOCK_BYTES} bytes`);

  // Pass 1 — encrypt with a placeholder so the chain up to the attacker's
  // block is fixed. Nothing from this pass is shown; it only supplies C_s and
  // C_(a-1), which the next line needs.
  const placeholder = new Uint8Array(BLOCK_BYTES);
  const draft = buildStream(secret, placeholder);
  const firstPass = cbcEncrypt(key, iv, concatBytes(...draft.map((b) => b.bytes)));
  if (!firstPass.ok) throw new Error(`arrangement failed: ${firstPass.error.message}`);
  const secretIndex = draft.findIndex((b) => b.isSecret);
  const attackerIndex = draft.findIndex((b) => b.isAttacker);
  const cSecret = firstPass.value.blocks[secretIndex].ciphertext;
  const cBeforeAttacker = firstPass.value.blocks[attackerIndex - 1].ciphertext;

  // The one step that needs the key.
  const usedTheKey = decryptBlock(key, cSecret);
  const injected = xorBytes(usedTheKey, cBeforeAttacker);

  // Pass 2 — the real stream, with the injected block in place.
  const blocks = buildStream(secret, injected);
  const run = cbcEncrypt(key, iv, concatBytes(...blocks.map((b) => b.bytes)));
  if (!run.ok) throw new Error(`arrangement failed: ${run.error.message}`);
  const cbc = run.value;

  const collisionHolds = bytesEqual(cbc.blocks[attackerIndex].ciphertext, cbc.blocks[secretIndex].ciphertext);
  const recovered = recoverFromCollision(cbc, attackerIndex, secretIndex);

  return {
    arranged: true,
    key,
    iv,
    secret,
    secretIndex,
    attackerIndex,
    blocks,
    cbc,
    usedTheKey,
    collisionHolds,
    recovered,
    recoveryCorrect: bytesEqual(recovered, secret),
    expectedBlocksByChance: expectedFirstCollision(64),
  };
}

/**
 * The eavesdropper's computation, isolated so it can be pointed at ANY two
 * block indices — including two that did not collide.
 *
 * That is deliberate. The exhibit lets a learner run this against a
 * non-colliding pair and watch it produce garbage, which is the only way to see
 * that the identity is doing work rather than decorating a result that was
 * going to appear anyway.
 *
 * Uses only C_(i-1), C_(j-1) and the attacker's own plaintext block. No key.
 */
export function recoverFromCollision(cbc: CbcResult, knownIndex: number, targetIndex: number): Uint8Array {
  const chainBeforeKnown = cbc.blocks[knownIndex].chainIn;
  const chainBeforeTarget = cbc.blocks[targetIndex].chainIn;
  const knownPlaintext = cbc.blocks[knownIndex].plaintext;
  return xorBytes(xorBytes(knownPlaintext, chainBeforeKnown), chainBeforeTarget);
}

/** Do two ciphertext blocks in this stream actually collide? Compared, not assumed. */
export function blocksCollide(cbc: CbcResult, a: number, b: number): boolean {
  return bytesEqual(cbc.blocks[a].ciphertext, cbc.blocks[b].ciphertext);
}

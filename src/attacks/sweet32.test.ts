import { describe, expect, it } from 'vitest';
import {
  arrangeCollision,
  blocksCollide,
  blocksForProbability,
  bytesForBlocks,
  collisionProbability,
  DEFAULT_SECRET,
  expectedFirstCollision,
  measureTruncatedCollision,
  recoverFromCollision,
  runTruncatedTrials,
} from './sweet32';
import { encryptBlock } from '../des/des';
import { BLOCK_BYTES, cbcEncrypt } from '../des/modes';
import { bytesEqual, fromUtf8, randomBytes, toHex, xorBytes } from '../des/bytes';
import { fixParity } from '../des/weakKeys';

const key = (): Uint8Array => fixParity(randomBytes(8));

describe('the birthday arithmetic', () => {
  it('gives the textbook 39% at the 2^32 bound for a 64-bit block', () => {
    expect(collisionProbability(2 ** 32, 64)).toBeCloseTo(1 - Math.exp(-0.5), 6);
    expect(collisionProbability(2 ** 32, 64)).toBeCloseTo(0.3935, 3);
  });

  it('is monotone and bounded', () => {
    expect(collisionProbability(0)).toBe(0);
    expect(collisionProbability(1)).toBe(0);
    let previous = 0;
    for (let log = 10; log <= 40; log += 2) {
      const p = collisionProbability(2 ** log, 64);
      expect(p).toBeGreaterThanOrEqual(previous);
      expect(p).toBeLessThanOrEqual(1);
      previous = p;
    }
  });

  it('blocksForProbability inverts collisionProbability', () => {
    for (const p of [0.1, 0.25, 0.5, 0.75, 0.9]) {
      const n = blocksForProbability(p, 64);
      expect(collisionProbability(n, 64)).toBeCloseTo(p, 6);
    }
  });

  /**
   * THE NEGATIVE CLAIM, as arithmetic: the bound depends only on the block
   * size. Every key length gives the same answer for the same block size, and
   * a longer block moves it while a longer key does not.
   */
  it('the bound depends on the block size and nothing else', () => {
    const at64 = expectedFirstCollision(64);
    expect(at64).toBeCloseTo(Math.sqrt((Math.PI / 2) * 2 ** 64), 0);
    // 3DES: 168-bit key, same 64-bit block, same bound. AES: 128-bit block.
    expect(expectedFirstCollision(64)).toBe(at64);
    expect(expectedFirstCollision(128) / at64).toBeGreaterThan(2 ** 31);
  });

  it('2^32 blocks is 32 GiB', () => {
    expect(bytesForBlocks(2 ** 32)).toBe(32 * 1024 ** 3);
    expect(bytesForBlocks(2 ** 20)).toBe(8 * 1024 ** 2);
  });
});

describe('the measured birthday curve', () => {
  it('finds a real truncated collision in real CBC output', async () => {
    const trial = await measureTruncatedCollision(key(), randomBytes(8), 16, 20000);
    expect(trial.exhausted).toBe(false);
    expect(trial.collisionAt).not.toBeNull();
    expect(trial.collidedWith).not.toBeNull();
    expect(trial.collidedWith as number).toBeLessThan(trial.collisionAt as number);
  });

  /**
   * Independent re-derivation of the reported collision: re-run CBC by hand
   * over the same key and IV and confirm the two named blocks really do agree
   * in their top `width` bits, and that no earlier pair did.
   */
  it('the reported collision is real and is the FIRST one', async () => {
    const k = key();
    const iv = randomBytes(8);
    const width: number = 14;
    const trial = await measureTruncatedCollision(k, iv, width, 50000);
    expect(trial.collisionAt).not.toBeNull();
    const i = trial.collisionAt as number;
    const j = trial.collidedWith as number;

    // Re-derive the ciphertext stream independently of the search.
    const { REQUEST_TEMPLATE } = await import('./sweet32');
    const blocks: Uint8Array[] = [];
    let chain = iv;
    for (let n = 0; n <= i; n++) {
      const at = (n * BLOCK_BYTES) % REQUEST_TEMPLATE.length;
      const plain = new Uint8Array(BLOCK_BYTES);
      for (let b = 0; b < BLOCK_BYTES; b++) plain[b] = REQUEST_TEMPLATE[(at + b) % REQUEST_TEMPLATE.length];
      chain = encryptBlock(k, xorBytes(plain, chain));
      blocks.push(chain);
    }
    const top = (block: Uint8Array): number => {
      const v = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) >>> 0;
      return width === 32 ? v : v >>> (32 - width);
    };
    expect(top(blocks[i])).toBe(top(blocks[j]));

    // No earlier pair collided: the search reported the first, not just one.
    const seen = new Map<number, number>();
    for (let n = 0; n < i; n++) {
      expect(seen.has(top(blocks[n]))).toBe(false);
      seen.set(top(blocks[n]), n);
    }
  });

  it('the mean first collision tracks sqrt(pi/2 * 2^w) across trials', async () => {
    const summary = await runTruncatedTrials(14, 24, 200000, key, () => randomBytes(8));
    expect(summary.completed).toBe(24);
    expect(summary.predictedMean).toBeCloseTo(Math.sqrt((Math.PI / 2) * 2 ** 14), 6);
    // Twenty-four samples of a distribution whose standard deviation is
    // comparable to its mean: the mean lands inside a wide but real band.
    expect(summary.ratio).toBeGreaterThan(0.55);
    expect(summary.ratio).toBeLessThan(1.75);
  }, 60_000);

  it('reports exhaustion honestly rather than inventing a collision', async () => {
    const trial = await measureTruncatedCollision(key(), randomBytes(8), 32, 40);
    expect(trial.exhausted).toBe(true);
    expect(trial.collisionAt).toBeNull();
    expect(trial.blocksScanned).toBe(40);
  });

  it('refuses a truncation width outside 8..32', async () => {
    await expect(measureTruncatedCollision(key(), randomBytes(8), 33, 10)).rejects.toThrow(/8\.\.32/);
    await expect(measureTruncatedCollision(key(), randomBytes(8), 7, 10)).rejects.toThrow(/8\.\.32/);
  });
});

describe('the arranged full collision', () => {
  it('really collides, and says it was arranged', () => {
    const session = arrangeCollision(key(), randomBytes(8));
    expect(session.arranged).toBe(true);
    expect(session.collisionHolds).toBe(true);
    expect(blocksCollide(session.cbc, session.attackerIndex, session.secretIndex)).toBe(true);
    // Compared here independently of the flag the module set.
    expect(toHex(session.cbc.blocks[session.attackerIndex].ciphertext)).toBe(
      toHex(session.cbc.blocks[session.secretIndex].ciphertext)
    );
  });

  it('recovers the secret block, and the secret is the cookie', () => {
    const session = arrangeCollision(key(), randomBytes(8));
    expect(session.recoveryCorrect).toBe(true);
    expect(bytesEqual(session.recovered, session.secret)).toBe(true);
    expect(fromUtf8(session.recovered)).toBe('s3cr3t42');
  });

  /**
   * Independent re-derivation: recompute the recovery from the ciphertext
   * stream alone, by hand, without calling the module's helper — and using only
   * values a passive eavesdropper can see.
   */
  it('the recovery uses only public values', () => {
    const session = arrangeCollision(key(), randomBytes(8));
    const cbc = session.cbc;
    const a = session.attackerIndex;
    const s = session.secretIndex;
    // C_(a-1) and C_(s-1) straight out of the ciphertext, not out of the trace.
    const cBeforeA = cbc.ciphertext.subarray((a - 1) * BLOCK_BYTES, a * BLOCK_BYTES);
    const cBeforeS = cbc.ciphertext.subarray((s - 1) * BLOCK_BYTES, s * BLOCK_BYTES);
    const attackerPlaintext = cbc.blocks[a].plaintext;
    const derived = xorBytes(xorBytes(attackerPlaintext, cBeforeA), cBeforeS);
    expect(toHex(derived)).toBe(toHex(session.secret));
  });

  it('the arrangement is the only place the key was used', () => {
    const k = key();
    const iv = randomBytes(8);
    const session = arrangeCollision(k, iv, DEFAULT_SECRET);
    // usedTheKey must be D_K(C_secret), and the injected block must be that
    // XOR the preceding ciphertext block.
    const injected = session.cbc.blocks[session.attackerIndex].plaintext;
    const before = session.cbc.blocks[session.attackerIndex - 1].ciphertext;
    expect(toHex(xorBytes(session.usedTheKey, before))).toBe(toHex(injected));
    expect(toHex(encryptBlock(k, session.usedTheKey))).toBe(
      toHex(session.cbc.blocks[session.secretIndex].ciphertext)
    );
  });

  it('the identity fails on a pair that did NOT collide', () => {
    const session = arrangeCollision(key(), randomBytes(8));
    // Pick a header block that is not the collision partner.
    const other = session.blocks.findIndex((b) => !b.isSecret && !b.isAttacker && b.index > 0);
    expect(blocksCollide(session.cbc, session.attackerIndex, other)).toBe(false);
    const garbage = recoverFromCollision(session.cbc, session.attackerIndex, other);
    expect(toHex(garbage)).not.toBe(toHex(session.blocks[other].bytes));
  });

  it('the stream is block-aligned and labelled', () => {
    const session = arrangeCollision(key(), randomBytes(8));
    for (const block of session.blocks) expect(block.bytes.length).toBe(BLOCK_BYTES);
    expect(session.blocks.filter((b) => b.isSecret)).toHaveLength(1);
    expect(session.blocks.filter((b) => b.isAttacker)).toHaveLength(1);
    expect(session.attackerIndex).toBeGreaterThan(session.secretIndex);
    expect(session.blocks.map((b) => b.index)).toEqual(session.blocks.map((_b, i) => i));
  });

  it('the stream really is what the CBC run encrypted', () => {
    const session = arrangeCollision(key(), randomBytes(8));
    session.blocks.forEach((block, i) => {
      expect(toHex(session.cbc.blocks[i].plaintext)).toBe(toHex(block.bytes));
    });
    const rebuilt = cbcEncrypt(
      session.key,
      session.iv,
      new Uint8Array(session.blocks.flatMap((b) => [...b.bytes]))
    );
    expect(rebuilt.ok).toBe(true);
    if (rebuilt.ok) expect(toHex(rebuilt.value.ciphertext)).toBe(toHex(session.cbc.ciphertext));
  });

  it('reports how long a real attacker would wait', () => {
    const session = arrangeCollision(key(), randomBytes(8));
    expect(session.expectedBlocksByChance).toBeCloseTo(expectedFirstCollision(64), 0);
    expect(session.expectedBlocksByChance).toBeGreaterThan(2 ** 32);
  });

  it('refuses a secret that is not one block', () => {
    expect(() => arrangeCollision(key(), randomBytes(8), new Uint8Array(7))).toThrow(/8 bytes/);
  });
});

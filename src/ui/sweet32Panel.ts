/**
 * Exhibit 5 — Sweet32. The climax, and the lab's negative claim.
 *
 * Four parts, in the order a learner needs them:
 *
 *  1. THE BOUND, AS LIVE ARITHMETIC. A slider over session size prints the
 *     collision probability and the data volume, side by side for a 64-bit and
 *     a 128-bit block. This is where "no key length repairs a block size"
 *     becomes visible: the key does not appear in the formula at all.
 *  2. THE CURVE, MEASURED ON THE REAL CIPHER. Real DES-CBC streams are
 *     encrypted until two ciphertext blocks agree in their top w bits. The
 *     measured mean first-collision index is compared against sqrt(pi/2 · 2^w).
 *     Truncated, and said so: a truncated collision reveals no plaintext.
 *  3. THE RECOVERY, ON AN ARRANGED FULL COLLISION. A genuine 64-bit collision
 *     is PLACED using the key — which a real attacker cannot do — and then the
 *     eavesdropper's arithmetic lifts the cookie out of it using only public
 *     values. The arrangement is stated in a banner that never goes away.
 *  4. THE DATA LIMIT. The same `checkDataLimit` the cipher enforces, driven by
 *     a slider, raising BLOCK_SIZE_EXCEEDED for a session too large.
 */
import {
  arrangeCollision,
  blocksCollide,
  blocksForProbability,
  bytesForBlocks,
  collisionProbability,
  expectedFirstCollision,
  recoverFromCollision,
  runTruncatedTrials,
} from '../attacks/sweet32';
import type { ArrangedCollision } from '../attacks/sweet32';
import { checkDataLimit, LIMIT_LEGACY_2_32, LIMIT_NONE, LIMIT_SP800_67R2 } from '../des/modes';
import type { DataLimit } from '../des/modes';
import { randomBytes, toHex, toPrintable, xorBytes } from '../des/bytes';
import { fixParity } from '../des/weakKeys';
import {
  append,
  bytes,
  button,
  card,
  clear,
  disclosure,
  el,
  intro,
  kv,
  learnerCheck,
  n,
  pill,
  pow2,
  rangeField,
  scroller,
  selectField,
  statusRegion,
  verdict,
} from './dom';

const LIMITS: Record<string, DataLimit> = {
  sp80067: LIMIT_SP800_67R2,
  legacy: LIMIT_LEGACY_2_32,
  none: LIMIT_NONE,
};

export function renderSweet32Panel(root: HTMLElement): void {
  clear(root);

  append(
    root,
    intro(
      'The failure a longer key cannot fix',
      el(
        'p',
        {},
        'DES encrypts 64 bits at a time. Chain enough of those blocks together under one key and ' +
          'two of the ciphertext blocks will eventually come out identical — not because the ' +
          'cipher is weak, but because there are only 2^64 possible blocks and you keep drawing ' +
          'from them. It is the birthday problem, and it bites after about four billion blocks.'
      ),
      el(
        'p',
        {},
        'In CBC that repeat is not harmless. CBC computes ',
        el('code', { text: 'C_i = E_K(P_i XOR C_{i-1})' }),
        ', and encryption is a permutation, so two equal outputs mean the two inputs were equal:'
      ),
      el('p', { class: 'hexline hex-hi' }, 'P_i XOR P_j  =  C_{i-1} XOR C_{j-1}'),
      el(
        'p',
        {},
        'The right-hand side is on the wire, in the clear. So a repeated ciphertext block hands ' +
          'an eavesdropper the XOR of two plaintext blocks — and if the attacker put one of them ' +
          'there themselves, the other one falls out whole. In 2016 Bhargavan and Leurent used ' +
          'exactly this to pull an authentication token out of a real HTTPS session that was ' +
          'still using 3DES (CVE-2016-2183).'
      ),
      el(
        'p',
        {},
        el('strong', { text: 'This is the point of the whole lab. ' }),
        '3DES has a 168-bit key and the same 64-bit block. Its birthday bound is in exactly the ' +
          'same place. Key length and block size are independent axes, and tripling the key moved ' +
          'only one of them. NIST’s eventual answer was not a longer key — it was a limit on how ' +
          'much you may encrypt.'
      )
    )
  );

  append(root, birthdayCard());
  append(root, measuredCard());
  append(root, recoveryCard());
  append(root, limitCard());

  append(
    root,
    learnerCheck({
      question:
        'A protocol switches from 3DES-CBC (64-bit block, 168-bit key) to AES-128-CBC (128-bit block, 128-bit key). The key got SHORTER. Did the birthday bound get better or worse?',
      options: [
        {
          text: 'Much better — the bound moved from 2^32 blocks to 2^64 blocks.',
          correct: true,
          why: 'Right. The bound is sqrt of the BLOCK space and the key length is not in the formula at all. Going from a 64-bit to a 128-bit block moves the collision point from about four billion blocks to about eighteen quintillion — from 32 GiB to 295 exabytes — while the key got 40 bits shorter. Two independent axes.',
        },
        {
          text: 'Worse — a shorter key always means less security.',
          correct: false,
          why: 'It means less security against key search, which is a different attack. Against the birthday bound the key length does nothing; the slider above never reads the key at all because the formula has no place to put it.',
        },
        {
          text: 'Unchanged — CBC has the same bound regardless of cipher.',
          correct: false,
          why: 'CBC has the same SHAPE of bound regardless of cipher, but the bound itself is sqrt(2^n) for an n-bit block, so the block size decides where it falls. Try both block sizes on the slider above.',
        },
      ],
    })
  );
}

// ── 1. The bound, as live arithmetic ────────────────────────────────────────

function birthdayCard(): HTMLElement {
  const out = statusRegion('Birthday bound readout');
  const { wrap, input } = rangeField(
    'sw-blocks',
    'Session size',
    { min: 8, max: 40, step: 1, value: 32 },
    (v) => `2^${v} blocks — ${bytes(bytesForBlocks(2 ** v))}`
  );

  function update(): void {
    const log = Number(input.value);
    const blocks = 2 ** log;
    const p64 = collisionProbability(blocks, 64);
    const p128 = collisionProbability(blocks, 128);
    clear(out);
    append(
      out,
      kv([
        ['Blocks encrypted', `${pow2(log)}`],
        ['Ciphertext volume', bytes(bytesForBlocks(blocks))],
        [
          '64-bit block (DES, 3DES, Blowfish)',
          el(
            'span',
            {},
            `${(p64 * 100).toPrecision(3)}% chance of a repeated block  `,
            p64 > 0.01 ? pill('bad', 'LEAKING') : p64 > 1e-6 ? pill('warn', 'CLOSE') : pill('ok', 'safe')
          ),
        ],
        [
          '128-bit block (AES)',
          el(
            'span',
            {},
            `${p128 < 1e-12 ? p128.toExponential(2) : (p128 * 100).toPrecision(3) + '%'} chance  `,
            p128 > 0.01 ? pill('bad', 'LEAKING') : pill('ok', 'safe')
          ),
        ],
      ]),
      el(
        'p',
        { class: 'field-help' },
        `50% likely after ${n(blocksForProbability(0.5, 64))} blocks (${bytes(
          bytesForBlocks(blocksForProbability(0.5, 64))
        )}) with a 64-bit block; the first collision arrives on average at block ${n(
          expectedFirstCollision(64)
        )}.`
      )
    );
  }

  input.addEventListener('input', update);
  const cardEl = card(
    'The bound, live',
    'Neither row below reads a key length. The formula has nowhere to put one.',
    el('div', { class: 'controls' }, wrap),
    out,
    disclosure(
      'The arithmetic',
      el(
        'p',
        {},
        'With D blocks drawn from N = 2^n possibilities, the chance that at least two agree is'
      ),
      el('p', { class: 'hexline hexline-dim' }, 'p  =  1 − Π(N−i)/N  ≥  1 − exp( −D(D−1) / 2N )'),
      el(
        'p',
        {},
        'At D = 2^(n/2) that is 1 − e^(−1/2) ≈ 0.39 — the "about 40% at the birthday bound" figure ' +
          'the Sweet32 paper quotes. The mean index of the FIRST collision is a different ' +
          'quantity, sqrt(π/2 · N), and that is the one the measurement below compares against.'
      ),
      el(
        'p',
        {},
        'n is the BLOCK size. The key length appears nowhere in either expression, which is the ' +
          'whole of the negative claim this lab makes.'
      )
    )
  );
  update();
  return cardEl;
}

// ── 2. The curve, measured ──────────────────────────────────────────────────

function measuredCard(): HTMLElement {
  const out = statusRegion('Measured birthday result');
  const progress = el('span', { class: 'meter-label', text: 'Idle.' });
  const { wrap: widthWrap, select: widthSelect } = selectField(
    'sw-width',
    'Compare how many leading bits?',
    [
      ['12', '12 bits — collides after ~80 blocks'],
      ['16', '16 bits — collides after ~320 blocks'],
      ['20', '20 bits — collides after ~1,300 blocks'],
      ['24', '24 bits — collides after ~5,100 blocks'],
    ],
    '16',
    'Truncating is what makes the birthday law reachable in a browser.'
  );
  const { wrap: trialWrap, select: trialSelect } = selectField(
    'sw-trials',
    'How many trials?',
    [
      ['8', '8 trials'],
      ['16', '16 trials'],
      ['32', '32 trials'],
    ],
    '16'
  );
  const runBtn = button('Measure it', 'btn-primary');

  runBtn.addEventListener('click', () => {
    void (async () => {
      runBtn.disabled = true;
      clear(out);
      const width = Number(widthSelect.value);
      const trials = Number(trialSelect.value);
      progress.textContent = 'Encrypting…';
      try {
        const summary = await runTruncatedTrials(
          width,
          trials,
          400_000,
          () => fixParity(randomBytes(8)),
          () => randomBytes(8),
          (trial) => {
            progress.textContent = `Trial ${Math.min(trial + 1, trials)} of ${trials}…`;
          }
        );
        progress.textContent = `Done in ${(summary.elapsedMs / 1000).toFixed(2)} s.`;
        const close = summary.ratio > 0.6 && summary.ratio < 1.6;
        append(
          out,
          kv([
            ['Bits compared', `${summary.width} of the 64 in each ciphertext block`],
            ['Trials that collided', `${summary.completed} of ${trials}`],
            ['Predicted first collision', `block ${n(summary.predictedMean)} — sqrt(π/2 · 2^${summary.width})`],
            ['Measured mean', `block ${n(summary.measuredMean)}`],
            ['Measured / predicted', summary.ratio.toFixed(3)],
          ]),
          close
            ? verdict(
                'pass',
                el('strong', { text: 'The birthday law holds on real DES output. ' }),
                `Measured ${n(summary.measuredMean)} against a predicted ${n(summary.predictedMean)}. ` +
                  'The same law, four billion times further along, is where a full 64-bit block collides.'
              )
            : verdict(
                'info',
                el('strong', { text: 'Wide of the prediction this time. ' }),
                `Measured ${n(summary.measuredMean)} against a predicted ${n(
                  summary.predictedMean
                )}. The first-collision index has a standard deviation comparable to its own mean, so ` +
                  `${trials} trials is a small sample — run more.`
              ),
          verdict(
            'alarm',
            el('strong', { text: 'A truncated collision reveals nothing. ' }),
            'These are real collisions in real ciphertext, but only in the leading bits. The CBC ' +
              'identity needs the FULL 64-bit block to match, which is why the recovery below has to ' +
              'be arranged rather than found.'
          )
        );
      } finally {
        runBtn.disabled = false;
      }
    })();
  });

  return card(
    'Measure the curve on the real cipher',
    'Real DES-CBC streams, run until two ciphertext blocks agree in their leading bits.',
    el(
      'p',
      {},
      'A full 64-bit collision needs about four billion blocks — 32 GiB — which no browser tab is ' +
        'going to produce. But the birthday law does not care how wide the space is, so shrink it: ' +
        'compare only the leading bits of each block and the same curve appears at a scale you can ' +
        'watch. Every block below is a real DES encryption in real CBC chaining.'
    ),
    el('div', { class: 'controls' }, widthWrap, trialWrap, el('div', { class: 'field' }, runBtn), el('div', { class: 'field' }, progress)),
    out
  );
}

// ── 3. The recovery ─────────────────────────────────────────────────────────

function recoveryCard(): HTMLElement {
  const out = statusRegion('Cookie recovery result');
  const streamHost = el('div', {});
  const newBtn = button('New session', 'btn-primary');
  const recoverBtn = button('Recover the cookie');
  const wrongBtn = button('Try the same arithmetic on a pair that did NOT collide', 'btn-danger');

  let session: ArrangedCollision = arrangeCollision(fixParity(randomBytes(8)), randomBytes(8));

  function drawStream(): void {
    clear(streamHost);
    const list = el('div', { class: 'strip', role: 'list' });
    session.blocks.forEach((block, i) => {
      const cipher = session.cbc.blocks[i].ciphertext;
      const collides = i === session.attackerIndex || i === session.secretIndex;
      const classes = [
        'strip-block',
        block.isSecret ? 'strip-secret' : '',
        block.isAttacker ? 'strip-attacker' : '',
        collides ? 'strip-collide' : '',
      ]
        .filter(Boolean)
        .join(' ');
      append(
        list,
        el(
          'div',
          { class: classes, role: 'listitem' },
          el('span', { class: 'strip-index', text: `BLOCK ${i}` }),
          el('strong', { text: block.isSecret ? '(hidden from the attacker)' : toPrintable(block.bytes) }),
          el('span', { text: `C = ${toHex(cipher)}` }),
          block.isSecret
            ? el('span', { class: 'strip-tag strip-tag-secret', text: '● the secret' })
            : block.isAttacker
              ? el('span', { class: 'strip-tag strip-tag-attacker', text: '● attacker-controlled' })
              : null,
          collides ? el('span', { class: 'strip-tag strip-tag-attacker', text: '● collision' }) : null
        )
      );
    });
    append(
      streamHost,
      scroller('The CBC ciphertext stream, block by block', 'strip-wrap', list),
      el('p', {
        class: 'field-help',
        text: `Blocks ${session.secretIndex} and ${session.attackerIndex} carry the same ciphertext. Everything else in the stream differs.`,
      })
    );
  }

  function recover(): void {
    clear(out);
    const recovered = recoverFromCollision(session.cbc, session.attackerIndex, session.secretIndex);
    const a = session.attackerIndex;
    const s = session.secretIndex;
    append(
      out,
      kv([
        [
          `C${a} and C${s}`,
          el(
            'span',
            {},
            el('span', { class: 'hexline hex-hi', text: toHex(session.cbc.blocks[a].ciphertext) }),
            ' ',
            blocksCollide(session.cbc, a, s) ? pill('bad', 'IDENTICAL') : pill('ok', 'different'),
          ),
        ],
        [`P${a} (attacker's own block)`, el('span', { class: 'hexline', text: toHex(session.blocks[a].bytes) })],
        [`C${a - 1}`, el('span', { class: 'hexline', text: toHex(session.cbc.blocks[a].chainIn) })],
        [`C${s - 1}`, el('span', { class: 'hexline', text: toHex(session.cbc.blocks[s].chainIn) })],
        [
          `P${s} = P${a} XOR C${a - 1} XOR C${s - 1}`,
          el('span', { class: 'hexline hex-hi', text: toHex(recovered) }),
        ],
        ['As text', el('span', { class: 'hexline hex-hi', text: toPrintable(recovered) })],
        ['The real cookie was', el('span', { class: 'hexline', text: toPrintable(session.secret) })],
      ]),
      session.recoveryCorrect
        ? verdict(
            'alarm',
            el('strong', { text: 'The cookie is out. ' }),
            'Every value in that computation is on the wire in the clear, except the attacker’s own ' +
              'plaintext block, which the attacker wrote. No key, no cryptanalysis, no fault — just ' +
              'two ciphertext blocks that happened to be equal.'
          )
        : verdict('fail', el('strong', { text: 'Recovery failed. ' }), 'The arithmetic in this page is wrong.')
    );
  }

  function recoverWrong(): void {
    clear(out);
    const other = session.blocks.findIndex((b) => !b.isSecret && !b.isAttacker && b.index > 0);
    const garbage = recoverFromCollision(session.cbc, session.attackerIndex, other);
    const collides = blocksCollide(session.cbc, session.attackerIndex, other);
    append(
      out,
      kv([
        [
          `C${session.attackerIndex} and C${other}`,
          el(
            'span',
            {},
            collides ? pill('bad', 'IDENTICAL') : pill('ok', 'different — no collision here'),
          ),
        ],
        ['What the identity produces', el('span', { class: 'hexline', text: toHex(garbage) })],
        ['As text', el('span', { class: 'hexline', text: toPrintable(garbage) })],
        [`The real block ${other}`, el('span', { class: 'hexline', text: toPrintable(session.blocks[other].bytes) })],
        [
          'Difference',
          el('span', { class: 'hexline', text: toHex(xorBytes(garbage, session.blocks[other].bytes)) }),
        ],
      ]),
      verdict(
        'info',
        el('strong', { text: 'Garbage, as it should be. ' }),
        'The identity is doing real work: it only holds when the two ciphertext blocks are actually ' +
          'equal. Without a collision there is nothing to recover, and this is what "nothing" looks ' +
          'like — the same arithmetic, applied where it does not apply.'
      )
    );
  }

  newBtn.addEventListener('click', () => {
    session = arrangeCollision(fixParity(randomBytes(8)), randomBytes(8));
    drawStream();
    clear(out);
  });
  recoverBtn.addEventListener('click', recover);
  wrongBtn.addEventListener('click', recoverWrong);

  const cardEl = card(
    'Lift the cookie out of the ciphertext',
    'A real DES-CBC session carrying a real secret. The collision is placed; everything after it is not.',
    el(
      'p',
      { class: 'arranged-banner' },
      el('span', { 'aria-hidden': 'true', text: '!' }),
      el(
        'span',
        {},
        el('strong', { text: 'ARRANGED COLLISION. ' }),
        'The full 64-bit collision below was PLACED using the key, by solving ',
        el('code', { text: 'P_a = D_K(C_s) XOR C_{a-1}' }),
        ' for one attacker block. A real attacker cannot do that — they wait about ',
        el('code', { text: '2^32' }),
        ' blocks (32 GiB) for chance to place it instead. What is not arranged: the cipher, the CBC ' +
          'chaining, the collision itself, and the arithmetic that recovers the cookie.'
      )
    ),
    streamHost,
    el(
      'div',
      { class: 'controls' },
      el('div', { class: 'field' }, recoverBtn),
      el('div', { class: 'field' }, wrongBtn),
      el('div', { class: 'field' }, newBtn)
    ),
    out
  );
  drawStream();
  return cardEl;
}

// ── 4. The data limit ───────────────────────────────────────────────────────

function limitCard(): HTMLElement {
  const out = statusRegion('Data limit verdict');
  const meterFill = el('div', { class: 'meter-fill' });
  const { wrap: sizeWrap, input: sizeInput } = rangeField(
    'sw-limit-blocks',
    'How much will you encrypt under this key?',
    { min: 10, max: 36, step: 1, value: 22 },
    (v) => `2^${v} blocks — ${bytes(bytesForBlocks(2 ** v))}`
  );
  const { wrap: policyWrap, select: policySelect } = selectField(
    'sw-limit-policy',
    'Policy in force',
    [
      ['sp80067', 'SP 800-67 Rev. 2 §3.4 — 2^20 blocks per key bundle'],
      ['legacy', 'The pre-2017 limit — 2^32 blocks'],
      ['none', 'No limit (deliberately broken)'],
    ],
    'sp80067'
  );

  function update(): void {
    const log = Number(sizeInput.value);
    const blocks = 2 ** log;
    const limit = LIMITS[policySelect.value];
    const result = checkDataLimit(blocks, limit);
    const fraction = Math.min(1, blocks / limit.maxBlocks);
    meterFill.style.width = `${(fraction * 100).toFixed(1)}%`;
    meterFill.className = result.ok ? 'meter-fill' : 'meter-fill meter-fill-over';
    clear(out);
    append(
      out,
      kv([
        ['Requested', `${pow2(log)} blocks — ${bytes(bytesForBlocks(blocks))}`],
        ['Limit', `${limit.label}`],
        ['Source', limit.citation],
        [
          'Collision probability at that size',
          `${(collisionProbability(blocks, 64) * 100).toPrecision(3)}%`,
        ],
      ]),
      result.ok
        ? verdict('pass', el('strong', { text: 'Permitted. ' }), 'Within the limit in force.')
        : verdict(
            'fail',
            el('span', { class: 'code-chip', text: result.error.code }),
            ' ',
            result.error.message
          )
    );
  }

  sizeInput.addEventListener('input', update);
  policySelect.addEventListener('change', update);

  const cardEl = card(
    'The policy failure a real library should raise',
    'This meter calls the same function the cipher calls. One rule, two readers.',
    el(
      'p',
      {},
      'Because the bound is a property of the block size, the only remaining defence is to stop ' +
        'encrypting before you reach it. NIST cut the TDEA limit from 2^32 blocks to 2^20 — from ' +
        '32 GiB to 8 MiB per key bundle — in direct response to Sweet32, then disallowed TDEA for ' +
        'applying protection after 31 December 2023 and withdrew SP 800-67 Rev. 2 entirely on ' +
        '1 January 2024.'
    ),
    el('div', { class: 'controls' }, sizeWrap, policyWrap),
    el('div', { class: 'meter' }, meterFill),
    out,
    disclosure(
      'What this lab does NOT claim',
      el(
        'p',
        {},
        el('strong', { text: 'Not: "3DES was fine except for the block size."' }),
        ' It was not. Two-key TDEA falls well below its nominal strength to known tradeoffs, and ' +
          'NIST’s deprecation cited key strength alongside the data limit. Those are real failures.'
      ),
      el(
        'p',
        {},
        el('strong', { text: 'The claim is narrower: those are separate axes. ' }),
        'Tripling the key repaired the key axis and left the block size exactly where it was. ' +
          'Whatever you do to a key, a 64-bit block still runs out of blocks after 2^32 of them.'
      ),
      el(
        'p',
        {},
        'The same bound is taught from two other directions elsewhere in this suite: ',
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-nonce-collision/', target: '_blank', rel: 'noopener noreferrer' }, 'Nonce Collision'),
        ' (the nonce space rather than the block space) and ',
        el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-collision-vault/', target: '_blank', rel: 'noopener noreferrer' }, 'Collision Vault'),
        ' (the hash output space).'
      )
    )
  );
  update();
  return cardEl;
}

/**
 * Exhibit 4 — 2DES falls to meeting in the middle.
 *
 * The attack runs for real, on the real cipher, over a reduced keyspace. Every
 * number describing the FULL attack is projected from the run the learner just
 * watched — its own operation count over its own elapsed time — so nothing on
 * screen is a figure typed into a template.
 *
 * The point being made is not "2DES is breakable". It is that DOUBLING THE KEY
 * BOUGHT ONE BIT: 2^57 work instead of 2^56, against a nominal 2^112. That is
 * the reason the answer was 3DES.
 */
import { meetInTheMiddle, projectToFullDes } from '../attacks/mitm';
import type { MitmResult } from '../attacks/mitm';
import { keyFromIndex } from '../attacks/complement';
import { parseHex, toHex } from '../des/bytes';
import {
  append,
  bytes,
  button,
  card,
  clear,
  disclosure,
  duration,
  el,
  intro,
  kv,
  learnerCheck,
  n,
  pill,
  pow2,
  retire,
  scroller,
  selectField,
  statusRegion,
  verdict,
} from './dom';

const BASE = '0101010101010101';
const P1 = '0123456789abcdef';
const P2 = 'fedcba9876543210';

export function renderMitmPanel(root: HTMLElement): void {
  clear(root);

  append(
    root,
    intro(
      'Why the answer was 3DES and not 2DES',
      el(
        'p',
        {},
        'When 56 bits stopped being enough, the obvious repair was to encrypt twice under two ' +
          'different keys. Two 56-bit keys look like 112 bits of security. They are worth ' +
          'about 57.'
      ),
      el(
        'p',
        {},
        'The attacker never searches the pair. Instead they attack the halves separately and meet ' +
          'in the middle: encrypt the known plaintext under every possible first key and store ' +
          'the results in a table, then decrypt the known ciphertext under every possible second ' +
          'key and look each result up. A hit means those two keys map P to C.'
      ),
      el(
        'p',
        {},
        el('strong', { text: 'Doubling the key added one bit and an exabyte of memory.' }),
        ' Diffie and Hellman published this in 1977, the same year DES was issued, and ' +
          'recommended triple encryption instead. Run it below on a keyspace small enough to ' +
          'finish while you watch.'
      )
    )
  );

  const { wrap: bitsWrap, select: bitsSelect } = selectField(
    'mitm-bits',
    'Reduced keyspace (each side)',
    [
      ['10', '10 bits — 1,024 keys per side'],
      ['12', '12 bits — 4,096 keys per side'],
      ['14', '14 bits — 16,384 keys per side'],
      ['16', '16 bits — 65,536 keys per side'],
    ],
    '12',
    'The remaining key bits are fixed and public. The cipher is the real DES throughout.'
  );
  const runBtn = button('Run the attack', 'btn btn-primary');
  const newKeysBtn = button('New victim keys');
  const progressLabel = el('span', { class: 'meter-label', text: 'Idle.' });
  const meterFill = el('div', { class: 'meter-fill' });
  const meter = el('div', { class: 'meter' }, meterFill);
  const output = statusRegion('Meet-in-the-middle result');

  const state = { k1: 0, k2: 0 };
  pickKeys();

  const setup = statusRegion('Victim setup');

  append(
    root,
    card(
      'The victim',
      'Two secret keys, drawn from the reduced space. The attacker sees only two plaintext/ciphertext pairs.',
      setup,
      el('div', { class: 'controls' }, bitsWrap, el('div', { class: 'field' }, newKeysBtn), el('div', { class: 'field' }, runBtn)),
      meter,
      progressLabel
    )
  );
  append(root, output);

  append(
    root,
    learnerCheck({
      question: 'The meet-in-the-middle table needs one entry per candidate first key. At the FULL width, how big is it?',
      options: [
        {
          text: 'About an exabyte — 2^56 entries.',
          correct: true,
          why: 'Right, and that is the real barrier rather than the time. Diffie and Hellman said so in 1977: the 2^56 encryptions and decryptions were "not unreasonable with current technology", but the memory was "several orders of magnitude above current capabilities". Time-memory tradeoffs shrink it at the cost of more work.',
        },
        {
          text: 'About a terabyte — the table only stores the keys that matched.',
          correct: false,
          why: 'The table has to be built BEFORE any match is known; it stores every intermediate value so the second phase has something to look up. That is one entry per candidate first key, all 2^56 of them.',
        },
        {
          text: 'It needs no table — you can stream both halves.',
          correct: false,
          why: 'Streaming both halves and comparing every pair is exactly the 2^112 search the attack avoids. The table is what turns a product into a sum, and the memory is the price.',
        },
      ],
    })
  );

  function pickKeys(): void {
    const bits = Number(bitsSelect?.value ?? '12');
    const span = 2 ** bits;
    const random = new Uint32Array(2);
    crypto.getRandomValues(random);
    state.k1 = random[0] % span;
    state.k2 = random[1] % span;
  }

  function showSetup(): void {
    clear(setup);
    const bits = Number(bitsSelect.value);
    append(
      setup,
      kv([
        ['Known pair 1', el('span', { class: 'hexline', text: `P = ${P1}` })],
        ['Known pair 2', el('span', { class: 'hexline', text: `P = ${P2}` })],
        ['Keys per side', n(2 ** bits)],
        ['Total pairs if searched naively', pow2(2 * bits)],
        [
          'Work the attack will do',
          `${n(2 * 2 ** bits)} DES operations — the SUM of the two halves, not their product`,
        ],
      ]),
      el('p', {
        class: 'field-help',
        text: 'The victim keys are hidden until the attack finds them; press "New victim keys" to draw a fresh pair.',
      })
    );
  }

  async function run(): Promise<void> {
    clear(output);
    ranBits = bitsSelect.value;
    runBtn.disabled = true;
    newKeysBtn.disabled = true;
    bitsSelect.disabled = true;
    const bits = Number(bitsSelect.value);
    if (state.k1 >= 2 ** bits || state.k2 >= 2 ** bits) pickKeys();
    meterFill.style.width = '0%';
    progressLabel.textContent = 'Building the table…';

    try {
      const result = await meetInTheMiddle({
        bits,
        base: hexOf(BASE),
        k1Index: state.k1,
        k2Index: state.k2,
        plaintexts: [hexOf(P1), hexOf(P2)],
        onProgress: (p) => {
          const half = p.phase === 'build' ? 0 : 0.5;
          meterFill.style.width = `${((half + (p.done / p.total) * 0.5) * 100).toFixed(1)}%`;
          progressLabel.textContent =
            p.phase === 'build'
              ? `Building the table: ${n(p.done)} of ${n(p.total)} first keys encrypted.`
              : `Meeting in the middle: ${n(p.done)} of ${n(p.total)} second keys decrypted.`;
        },
      });
      meterFill.style.width = '100%';
      progressLabel.textContent = `Done in ${(result.elapsedMs / 1000).toFixed(2)} s.`;
      renderResult(result);
    } finally {
      runBtn.disabled = false;
      newKeysBtn.disabled = false;
      bitsSelect.disabled = false;
    }
  }

  function renderResult(result: MitmResult): void {
    clear(output);
    const found = result.confirmed;
    const projection = projectToFullDes(result);
    const trueK1 = keyFromIndex(result.trueIndices[0], result.bits, hexOf(BASE));
    const trueK2 = keyFromIndex(result.trueIndices[1], result.bits, hexOf(BASE));
    const correct =
      found !== null && toHex(found.k1) === toHex(trueK1) && toHex(found.k2) === toHex(trueK2);

    append(
      output,
      card(
        'What the attack recovered',
        `${n(result.desOperations)} DES block operations in ${(result.elapsedMs / 1000).toFixed(2)} s.`,
        found
          ? kv([
              ['K1 recovered', el('span', { class: 'hexline hex-hi', text: toHex(found.k1) })],
              ['K2 recovered', el('span', { class: 'hexline hex-hi', text: toHex(found.k2) })],
              ['K1 the victim used', el('span', { class: 'hexline', text: toHex(trueK1) })],
              ['K2 the victim used', el('span', { class: 'hexline', text: toHex(trueK2) })],
              [
                'Meeting value',
                el('span', { class: 'hexline', text: `E_K1(P) = D_K2(C) = ${toHex(found.middle)}` }),
              ],
              ['Table entries stored', n(result.tableEntries)],
              ['Candidates from pair 1', n(result.candidates.length)],
              ['Ruled out by pair 2', n(result.falsePositives)],
            ])
          : el('p', { text: 'No candidate survived both known pairs.' }),
        correct
          ? verdict(
              'alarm',
              el('strong', { text: 'Both keys recovered. ' }),
              `The attack performed ${n(result.desOperations)} DES operations against a keyspace of ` +
                `${pow2(2 * result.bits)} key pairs. The work was the SUM of the two halves, not the product.`
            )
          : verdict(
              'fail',
              el('strong', { text: 'Recovery failed. ' }),
              'The search did not land on the keys the victim used, which means the attack code in this page is wrong.'
            ),
        result.candidates.length > 1 ? candidateTable(result) : null
      )
    );

    append(
      output,
      card(
        'The same attack at full size',
        'Projected from the run you just watched — the rate below is this browser’s measured rate.',
        kv([
          ['Keys per side', pow2(56)],
          ['Nominal 2DES keyspace', pow2(projection.bruteForceLog2)],
          ['Meet-in-the-middle work', `${pow2(projection.fullOpsLog2)} DES operations`],
          [
            'Effective security',
            `${projection.effectiveBits} bits — one more than single DES's 56`,
          ],
          ['Table size', bytes(2 ** projection.fullTableBytesLog2)],
          [
            'Candidates after ONE known pair',
            `${pow2(projection.falsePositivesLog2)} — which is why a second pair is not optional`,
          ],
          ['This browser managed', `${n(projection.measuredOpsPerSecond)} DES operations per second`],
          [
            'So the full attack would take',
            `${duration(projection.secondsAtMeasuredRate)} at that rate`,
          ],
        ]),
        verdict(
          'info',
          el('strong', { text: 'The wall-clock figure is this implementation, not the state of the art. ' }),
          'The DES here is written for readability, not speed — a bit-sliced native implementation is ' +
            'orders of magnitude faster and dedicated hardware faster still. What does NOT change with ' +
            'a faster machine is the shape: 2^57 against a nominal 2^112, and a table nobody can build.'
        ),
        disclosure(
          'What 3DES did about it, and what it did not',
          el(
            'p',
            {},
            'Triple DES applies the cipher three times (encrypt, decrypt, encrypt) under two or ' +
              'three keys. Meeting in the middle against the three-key variant costs about 2^112 ' +
              'rather than 2^168, so the key axis really was repaired — imperfectly, and the ' +
              'two-key variant falls well below its nominal strength to known tradeoffs, which ' +
              'is why NIST disallowed it for applying protection from 2016.'
          ),
          el(
            'p',
            {},
            el('strong', { text: 'The block size was never touched.' }),
            ' 3DES has a 168-bit key and the same 64-bit block DES had, so its birthday bound sits ' +
              'exactly where DES’s did. That is the Sweet32 exhibit, and it is the point this lab ' +
              'exists to make: these are two independent axes, and lengthening the key moved only one.'
          )
        )
      )
    );
  }

  // A recovered key pair describes the keys the victim was using and the width
  // it was found at. Change either and the printed pair is about a victim who
  // no longer exists, so it is retired rather than left sitting there.
  let ranBits = bitsSelect.value;
  const invalidate = (because: string): void => {
    pickKeys();
    showSetup();
    if (output.firstChild) retire(output, 'That recovered key pair', because);
    meterFill.style.width = '0%';
    progressLabel.textContent = 'Idle.';
  };
  bitsSelect.addEventListener('change', () => {
    // No-op guard: re-selecting the width already in force keeps the result.
    if (bitsSelect.value === ranBits) return;
    ranBits = bitsSelect.value;
    invalidate('the keyspace width changed');
  });
  newKeysBtn.addEventListener('click', () => invalidate('the victim drew new keys'));
  runBtn.addEventListener('click', () => {
    void run();
  });

  showSetup();
}

function candidateTable(result: MitmResult): HTMLElement {
  const body = el('tbody');
  for (const candidate of result.candidates.slice(0, 40)) {
    append(
      body,
      el(
        'tr',
        {},
        el('td', { text: toHex(candidate.k1) }),
        el('td', { text: toHex(candidate.k2) }),
        el('td', { text: toHex(candidate.middle) }),
        el('td', {}, candidate.survivesSecondPair ? pill('bad', 'SURVIVES') : pill('neutral', 'ruled out'))
      )
    );
  }
  const table = scroller(
    'Candidate key pairs and the second-pair sieve',
    'table-scroll',
    el(
      'table',
      {},
      el(
        'thead',
        {},
        el(
          'tr',
          {},
          el('th', { scope: 'col', text: 'K1' }),
          el('th', { scope: 'col', text: 'K2' }),
          el('th', { scope: 'col', text: 'Meeting value' }),
          el('th', { scope: 'col', text: 'Second pair' })
        )
      ),
      body
    )
  );
  return el(
    'div',
    {},
    el('h4', { text: 'Candidates the first pair could not separate' }),
    table,
    result.candidates.length > 40
      ? el('p', {
          class: 'field-help',
          text: `Showing the first 40 of ${result.candidates.length} candidates.`,
        })
      : null
  );
}

function hexOf(text: string): Uint8Array {
  const parsed = parseHex(text, 8);
  if (!parsed.ok) throw new Error(`bad shipped constant: ${text}`);
  return parsed.value;
}

/**
 * Exhibit 3 — Complementation, and the one bit it costs.
 *
 * Two halves:
 *
 *  1. THE IDENTITY, COMPUTED ON BOTH SIDES AND COMPARED. DES(~K, ~P) is
 *     obtained by running the cipher on complemented inputs; ~DES(K, P) is
 *     obtained by flipping bits of an ordinary ciphertext. Two different
 *     routes, compared byte for byte — not one value printed twice.
 *  2. THE SAVING, MEASURED. Two brute-force searches race over the same
 *     reduced keyspace against the same target, and each reports the
 *     encryptions it actually performed. The ratio is read off the counters.
 *
 * The striking case is the second toggle: hide the key in the complement half
 * and the plain search sweeps the entire space and finds nothing, while the
 * complementation search finds it at the same index it always would have.
 */
import { complementWitness, raceSearches } from '../attacks/complement';
import { parseHex, randomBytes, toHex } from '../des/bytes';
import { parseKeyStrict } from '../des/weakKeys';
import {
  append,
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
  retire,
  selectField,
  statusRegion,
  textField,
  verdict,
} from './dom';

const DEFAULT_KEY = '133457799bbcdff1';
const DEFAULT_BLOCK = '0123456789abcdef';
const SEARCH_BASE = '0101010101010101';

export function renderComplementPanel(root: HTMLElement): void {
  clear(root);

  append(
    root,
    intro(
      'One free bit off the brute force',
      el(
        'p',
        {},
        'Flip every bit of the key and every bit of the plaintext, and DES hands back a ' +
          'ciphertext with every bit flipped. Nothing about the cipher is broken by that — but ' +
          'it means an attacker testing one candidate key learns the answer for two.'
      ),
      el(
        'p',
        {},
        'It falls out of the structure. The subkeys are only SELECTED bits of the key, so a ' +
          'complemented key gives complemented subkeys; the expansion E only selects bits, so a ' +
          'complemented R gives a complemented E(R). Complement both sides of an XOR and the XOR ' +
          'is unchanged — so every S-box sees the same six bits it would have seen, and the ' +
          'complement rides through the cipher untouched.'
      ),
      el(
        'p',
        {},
        el('strong', { text: 'The cost is exactly one bit: 2^55 expected trials instead of 2^54.' }),
        ' It never grew into anything larger, and it needs chosen plaintext. Small — but DES had ' +
          'no bits to spare.'
      )
    )
  );

  // ── The identity ────────────────────────────────────────────────────────
  const { wrap: keyWrap, input: keyInput } = textField('comp-key', 'Key (16 hex digits)', DEFAULT_KEY);
  const { wrap: blockWrap, input: blockInput } = textField('comp-block', 'Plaintext (16 hex digits)', DEFAULT_BLOCK);
  const checkBtn = button('Compute both sides', 'btn btn-primary');
  const randomBtn = button('Random pair');
  const identityOut = statusRegion('Complementation identity result');

  append(
    root,
    card(
      'Compute both sides, then compare',
      'Two different routes to the same 64 bits.',
      el('div', { class: 'controls' }, keyWrap, blockWrap, el('div', { class: 'field' }, checkBtn), el('div', { class: 'field' }, randomBtn)),
      identityOut
    )
  );

  // ── The race ────────────────────────────────────────────────────────────
  const { wrap: widthWrap, select: widthSelect } = selectField(
    'comp-width',
    'Search width',
    [
      ['8', '8 bits — 256 candidate keys'],
      ['10', '10 bits — 1,024 candidate keys'],
      ['12', '12 bits — 4,096 candidate keys'],
      ['14', '14 bits — 16,384 candidate keys'],
    ],
    '12',
    'The other 44+ key bits are fixed and public, so the search finishes in a browser.'
  );
  const { wrap: halfWrap, select: halfSelect } = selectField(
    'comp-half',
    'Where the real key hides',
    [
      ['direct', 'In the swept space — both searches can find it'],
      ['complement', 'In the COMPLEMENT of the swept space'],
    ],
    'direct'
  );
  const raceBtn = button('Race the two searches', 'btn btn-primary');
  const raceOut = statusRegion('Search race result');

  append(
    root,
    card(
      'Break it yourself: race the two searches',
      'Both hunt the same key over the same space. The counters are the claim.',
      el(
        'p',
        {},
        'The clever search asks for two ciphertexts up front — ',
        el('code', { text: 'C1 = DES(K, P)' }),
        ' and ',
        el('code', { text: 'C2 = DES(K, ~P)' }),
        ' — and then tests each candidate ',
        el('code', { text: "K'" }),
        ' once, checking its result against both ',
        el('code', { text: 'C1' }),
        ' and ',
        el('code', { text: '~C2' }),
        '. A hit on the second means the real key is ',
        el('code', { text: "~K'" }),
        '.'
      ),
      el(
        'div',
        { class: 'controls' },
        widthWrap,
        halfWrap,
        el('div', { class: 'field' }, raceBtn)
      ),
      raceOut,
      disclosure(
        'Why the second check works',
        el('p', {}, 'Suppose the real key K is the complement of the candidate K\'. Then'),
        el('p', { class: 'hexline hexline-dim' }, 'C2 = DES(K, ~P) = DES(~K\', ~P) = ~DES(K\', P) = ~X'),
        el(
          'p',
          {},
          'so ',
          el('code', { text: 'X = ~C2' }),
          '. One encryption, two keys ruled in or out. Nothing about the cipher had to be broken ' +
            'to get that — it is a structural consequence of using XOR to mix the key in.'
        )
      )
    )
  );

  append(
    root,
    learnerCheck({
      question: 'Does the complementation property help against a KNOWN-plaintext attacker (one who cannot choose P)?',
      options: [
        {
          text: 'No — the attacker needs both P and ~P encrypted, which means choosing them.',
          correct: true,
          why: 'Correct. The trick needs a chosen-plaintext pair (P, ~P). With only whatever plaintext happened to be sent, there is no second ciphertext to compare against and the search is back to one key per encryption. The Handbook of Applied Cryptography makes exactly this point in §7.4.3.',
        },
        {
          text: 'Yes — the property holds for any plaintext.',
          correct: false,
          why: 'The IDENTITY holds for any plaintext, but the SAVING does not. You need the ciphertext of ~P specifically, and a known-plaintext attacker cannot ask for it.',
        },
        {
          text: 'Yes, and it halves the work again for each extra pair.',
          correct: false,
          why: 'It is one bit, once. There is no stacking: complementing twice returns you to where you started, so the trick partitions the keyspace into pairs and that is all.',
        },
      ],
    })
  );

  // ── Wiring ──────────────────────────────────────────────────────────────

  function showIdentity(): void {
    clear(identityOut);
    const parsedKey = parseKeyStrict(keyInput.value, { allowWeak: true });
    if (!parsedKey.ok) {
      keyInput.setAttribute('aria-invalid', 'true');
      append(identityOut, verdict('fail', el('span', { class: 'code-chip', text: parsedKey.error.code }), ' ', parsedKey.error.message));
      return;
    }
    keyInput.setAttribute('aria-invalid', 'false');
    const parsedBlock = parseHex(blockInput.value, 8);
    if (!parsedBlock.ok) {
      blockInput.setAttribute('aria-invalid', 'true');
      append(identityOut, verdict('fail', el('span', { class: 'code-chip', text: parsedBlock.error.code }), ' ', parsedBlock.error.message));
      return;
    }
    blockInput.setAttribute('aria-invalid', 'false');

    const witness = complementWitness(parsedKey.value.key, parsedBlock.value);
    append(
      identityOut,
      kv([
        ['K', el('span', { class: 'hexline', text: toHex(witness.key) })],
        ['P', el('span', { class: 'hexline', text: toHex(witness.plaintext) })],
        ['DES(K, P)', el('span', { class: 'hexline', text: toHex(witness.ciphertext) })],
        ['~K', el('span', { class: 'hexline', text: toHex(witness.keyComplement) })],
        ['~P', el('span', { class: 'hexline', text: toHex(witness.plaintextComplement) })],
        [
          'DES(~K, ~P) — cipher run',
          el('span', { class: 'hexline hex-hi', text: toHex(witness.ciphertextOfComplements) }),
        ],
        [
          '~DES(K, P) — bits flipped',
          el('span', { class: 'hexline hex-hi', text: toHex(witness.complementOfCiphertext) }),
        ],
      ]),
      witness.holds
        ? verdict(
            'pass',
            el('strong', { text: 'The two agree, byte for byte. ' }),
            'One value came out of a DES encryption of complemented inputs; the other came from ' +
              'flipping the bits of an ordinary ciphertext. They were never the same computation.'
          )
        : verdict('fail', el('strong', { text: 'They disagree. ' }), 'The cipher in this page is broken.')
    );
  }

  function race(): void {
    clear(raceOut);
    ranWidth = widthSelect.value;
    ranHalf = halfSelect.value;
    const bits = Number(widthSelect.value);
    const useComplementHalf = halfSelect.value === 'complement';
    const base = hexOf(SEARCH_BASE);
    const plaintext = hexOf(DEFAULT_BLOCK);
    const targetIndex = Math.floor(2 ** bits * 0.62);
    const result = raceSearches(targetIndex, useComplementHalf, bits, base, plaintext);

    const rows: (readonly [string, HTMLElement | string])[] = [
      ['Real key', el('span', { class: 'hexline hex-hi', text: toHex(result.targetKey) })],
      [
        'Hidden as',
        useComplementHalf
          ? el('span', {}, 'the complement of index ', el('code', { text: String(targetIndex) }), ' in the swept space')
          : el('span', {}, 'index ', el('code', { text: String(targetIndex) }), ' in the swept space'),
      ],
      ['Space swept', `${n(2 ** bits)} candidate keys (${bits} bits)`],
      ['Plain: encryptions', n(result.plain.encryptions)],
      ['Plain: keys covered', n(result.plain.keysCovered)],
      [
        'Plain: outcome',
        result.plain.key
          ? el('span', {}, pill('ok', 'FOUND'), ' ', el('code', { text: toHex(result.plain.key) }))
          : el('span', {}, pill('bad', 'NOT FOUND'), ' swept the whole space'),
      ],
      ['Complementation: encryptions', n(result.clever.encryptions)],
      ['Complementation: keys covered', n(result.clever.keysCovered)],
      [
        'Complementation: outcome',
        result.clever.key
          ? el(
              'span',
              {},
              pill('ok', 'FOUND'),
              ' ',
              el('code', { text: toHex(result.clever.key) }),
              result.clever.foundAsComplement ? ' — as the complement of the tested candidate' : ''
            )
          : el('span', {}, pill('bad', 'NOT FOUND'), ' swept the whole space'),
      ],
      ['Keys per encryption, plain', result.plainKeysPerEncryption.toFixed(2)],
      ['Keys per encryption, clever', result.cleverKeysPerEncryption.toFixed(2)],
    ];

    append(
      raceOut,
      kv(rows),
      useComplementHalf
        ? verdict(
            'alarm',
            el('strong', { text: 'The plain search missed it entirely. ' }),
            `It performed ${n(result.plain.encryptions)} encryptions and ruled out ${n(
              result.plain.keysCovered
            )} keys — every one in the space, and the real key was not among them. The complementation ` +
              `search found it after ${n(result.clever.encryptions)} encryptions, because each of those ` +
              'encryptions answered for a key AND its complement.'
          )
        : verdict(
            'info',
            el('strong', { text: 'Same encryptions, twice the coverage. ' }),
            `Both searches performed ${n(result.clever.encryptions)} encryptions. The plain one ruled ` +
              `out ${n(result.plain.keysCovered)} keys; the clever one ruled out ${n(
                result.clever.keysCovered
              )} — a factor of ${(result.cleverKeysPerEncryption / result.plainKeysPerEncryption).toFixed(0)}. ` +
              'Switch the second control to hide the key in the complement half to see the sharper version.'
          ),
      el(
        'p',
        { class: 'field-help' },
        `At the full width this is 2^55 expected trials instead of 2^54 — one bit off a 56-bit key. ` +
          `The swept keys here all share the base ${SEARCH_BASE} outside the ${bits} varied bits, ` +
          'which is what makes the search finish while you watch.'
      )
    );
  }

  checkBtn.addEventListener('click', showIdentity);
  randomBtn.addEventListener('click', () => {
    keyInput.value = toHex(randomBytes(8));
    blockInput.value = toHex(randomBytes(8));
    showIdentity();
  });
  raceBtn.addEventListener('click', race);

  // The race's counters describe the width and the half it ran at, so changing
  // either makes the printed result describe inputs that are no longer on
  // screen. Re-selecting the SAME option changes nothing and must not retire a
  // fresh result — hence the guards.
  let ranWidth = widthSelect.value;
  let ranHalf = halfSelect.value;
  const retireRace = (because: string): void => {
    if (!raceOut.firstChild) return;
    retire(raceOut, 'That search result', because);
  };
  widthSelect.addEventListener('change', () => {
    if (widthSelect.value === ranWidth) return;
    ranWidth = widthSelect.value;
    retireRace('the search width changed');
  });
  halfSelect.addEventListener('change', () => {
    if (halfSelect.value === ranHalf) return;
    ranHalf = halfSelect.value;
    retireRace('the key is now hidden somewhere else');
  });

  showIdentity();
  race();
}

function hexOf(text: string): Uint8Array {
  const parsed = parseHex(text, 8);
  if (!parsed.ok) throw new Error(`bad shipped constant: ${text}`);
  return parsed.value;
}

// [extension] point — a chosen-plaintext panel letting the learner supply the
// pair (P, ~P) themselves would slot in beside `race()`, reusing
// `keyFromIndex` and `complementBytes` from the attack module. Not built.

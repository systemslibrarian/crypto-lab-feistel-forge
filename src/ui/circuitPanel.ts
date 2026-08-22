/**
 * Exhibit 2 — Same Circuit Both Ways.
 *
 * Two claims, both shown by running the cipher rather than by asserting them:
 *
 *  1. DECRYPTION IS THE ENCRYPTION CIRCUIT WITH THE SCHEDULE REVERSED. The
 *     panel prints both subkey lists side by side so a reader can see K1..K16
 *     against K16..K1, and then compares D(E(P)) against P byte for byte.
 *  2. FOR FOUR KEYS THE TWO SCHEDULES ARE THE SAME LIST, so encryption becomes
 *     its own inverse. The panel runs E twice under a weak key and lands back
 *     on the plaintext — and shows WHY, by printing the sixteen subkeys and
 *     the C0/D0 registers that made them identical.
 *
 * The key-policy failures are wired here too: WEAK_KEY, SEMI_WEAK_KEY and
 * PARITY_INVALID are raised by the same `parseKeyStrict` the rest of the lab
 * uses, and the panel names the code it got back rather than paraphrasing it.
 */
import { keySchedule } from '../des/des';
import { bytesEqual, parseHex, randomBytes, toHex } from '../des/bytes';
import { decryptBlock, encryptBlock } from '../des/des';
import {
  doubleEncrypt,
  fixParity,
  inspectKey,
  parseKeyStrict,
  SEMI_WEAK_PAIRS,
  weakKeyReason,
  WEAK_KEYS,
} from '../des/weakKeys';
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
  pill,
  scroller,
  statusRegion,
  textField,
  verdict,
} from './dom';

const DEFAULT_KEY = '133457799bbcdff1';
const DEFAULT_BLOCK = '0123456789abcdef';

export function renderCircuitPanel(root: HTMLElement): void {
  clear(root);

  append(
    root,
    intro(
      'Why decryption needs no new hardware',
      el(
        'p',
        {},
        'A Feistel round is undone by running the same round with the same subkey. Do that for ' +
          'all sixteen rounds and you have decryption — the identical circuit, fed the subkeys ' +
          'in the opposite order. In 1977 that mattered enormously: one chip did both jobs.'
      ),
      el(
        'p',
        {},
        'The key schedule makes it work. DES rotates two 28-bit registers by amounts that sum to ' +
          '28, so after sixteen rounds they are back where they started. Which raises an ' +
          'uncomfortable question: what if rotating them changes nothing at all?'
      ),
      el(
        'p',
        {},
        el('strong', { text: 'Four keys have exactly that property.' }),
        ' Their two registers are all-zeros or all-ones, every round gets the same subkey, the ' +
          'reversed schedule equals the forward one — and encrypting twice gives you your ' +
          'plaintext back. Load one below and watch it happen.'
      )
    )
  );

  // ── The round trip ──────────────────────────────────────────────────────
  const { wrap: keyWrap, input: keyInput } = textField(
    'circuit-key',
    'Key (16 hex digits)',
    DEFAULT_KEY,
    'Refused if the parity is wrong or the key is weak — unless you tick the box below.'
  );
  const { wrap: blockWrap, input: blockInput } = textField(
    'circuit-block',
    'Plaintext block (16 hex digits)',
    DEFAULT_BLOCK
  );
  const allowWeak = el('input', { type: 'checkbox', id: 'circuit-allow-weak' });
  const allowWrap = el(
    'div',
    { class: 'field' },
    el('label', { class: 'field-label', for: 'circuit-allow-weak', text: 'Deliberately broken mode' }),
    el(
      'span',
      { class: 'field-help' },
      allowWeak,
      ' ',
      el('label', { for: 'circuit-allow-weak', text: 'Load weak and semi-weak keys anyway' })
    )
  );
  const runBtn = button('Encrypt, then decrypt', 'btn-primary');
  const randomBtn = button('Random healthy key');
  const output = statusRegion('Round-trip result');

  append(
    root,
    card(
      'One circuit, two directions',
      'Encrypt, then decrypt with the same circuit and the schedule reversed.',
      el(
        'div',
        { class: 'controls' },
        keyWrap,
        blockWrap,
        allowWrap,
        el('div', { class: 'field' }, runBtn),
        el('div', { class: 'field' }, randomBtn)
      ),
      output
    )
  );

  // ── The weak keys ───────────────────────────────────────────────────────
  const weakOutput = statusRegion('Weak key result');
  const weakButtons = el('div', { class: 'seg' });
  for (const weak of WEAK_KEYS) {
    const btn = button(weak, 'seg-btn');
    btn.addEventListener('click', () => showWeak(weak));
    append(weakButtons, btn);
  }
  const healthyBtn = button('A healthy key, for contrast', 'seg-btn');
  healthyBtn.addEventListener('click', () => showWeak(DEFAULT_KEY));
  append(weakButtons, healthyBtn);

  append(
    root,
    card(
      'The four keys where encryption IS decryption',
      'Pick one. The cipher runs twice; nothing is asserted.',
      el('p', { class: 'field-help', text: 'Encrypt the block, then encrypt the result again under the same key.' }),
      weakButtons,
      weakOutput,
      disclosure(
        'Semi-weak keys — the same collapse, spread over two keys',
        el(
          'p',
          {},
          'Six PAIRS of keys generate only two distinct subkeys each, arranged so that one key’s ' +
            'schedule is the other’s reversed. Encrypting under one is decrypting under the other. ' +
            'They are refused here for the same reason the weak keys are.'
        ),
        semiWeakTable()
      )
    )
  );

  append(
    root,
    learnerCheck({
      question:
        'DES key bytes carry odd parity. If you flip a parity bit, what happens to the ciphertext?',
      options: [
        {
          text: 'Nothing — PC-1 drops the parity bits before the schedule sees them.',
          correct: true,
          why: 'Right, and that is why this lab treats PARITY_INVALID as a transmission failure rather than a strength failure. The key you loaded is not the key somebody sent you, and a library that shrugs at that has checked nothing. The 56 bits that matter are untouched.',
        },
        {
          text: 'The ciphertext changes — all 64 bits are key bits.',
          correct: false,
          why: 'Only 56 are. PC-1 selects 56 of the 64 and the eight it drops are exactly bits 8, 16, 24 … 64: the parity bits. The unit tests assert that flipping all eight leaves every subkey identical.',
        },
        {
          text: 'The cipher refuses to run.',
          correct: false,
          why: 'DES itself has no opinion — it never looks at those bits. Refusing is a POLICY this lab applies on top, which is the point: somebody has to check, and historically almost nobody did.',
        },
      ],
    })
  );

  // ── Wiring ──────────────────────────────────────────────────────────────

  function runRoundTrip(): void {
    clear(output);
    const parsedKey = parseKeyStrict(keyInput.value, { allowWeak: allowWeak.checked });
    if (!parsedKey.ok) {
      keyInput.setAttribute('aria-invalid', 'true');
      append(
        output,
        verdict(
          'fail',
          el('span', { class: 'code-chip', text: parsedKey.error.code }),
          ' ',
          parsedKey.error.message,
          parsedKey.error.code === 'WEAK_KEY' || parsedKey.error.code === 'SEMI_WEAK_KEY'
            ? ' Tick "Deliberately broken mode" to load it anyway.'
            : ''
        )
      );
      return;
    }
    keyInput.setAttribute('aria-invalid', 'false');
    const parsedBlock = parseHex(blockInput.value, 8);
    if (!parsedBlock.ok) {
      blockInput.setAttribute('aria-invalid', 'true');
      append(
        output,
        verdict('fail', el('span', { class: 'code-chip', text: parsedBlock.error.code }), ' ', parsedBlock.error.message)
      );
      return;
    }
    blockInput.setAttribute('aria-invalid', 'false');

    const key = parsedKey.value.key;
    const block = parsedBlock.value;
    const ciphertext = encryptBlock(key, block);
    const recovered = decryptBlock(key, ciphertext);
    const forward = keySchedule(key).subkeys.map(toHex);
    const reverse = [...forward].reverse();
    const identical = forward.join('|') === reverse.join('|');

    append(
      output,
      kv([
        ['Plaintext', el('span', { class: 'hexline', text: toHex(block) })],
        ['Ciphertext', el('span', { class: 'hexline hex-hi', text: toHex(ciphertext) })],
        ['Decrypted', el('span', { class: 'hexline', text: toHex(recovered) })],
      ]),
      bytesEqual(recovered, block)
        ? verdict(
            'pass',
            el('strong', { text: 'Recovered, byte for byte. ' }),
            'The decryption ran the same sixteen-round circuit with the subkeys replayed backwards.'
          )
        : verdict('fail', el('strong', { text: 'Round trip failed. ' }), 'The cipher in this page is broken.'),
      scheduleTable(forward, reverse),
      identical
        ? verdict(
            'alarm',
            el('strong', { text: 'The two schedules are the same list. ' }),
            'Forward and reversed are indistinguishable, so encryption is its own inverse under this key. ' +
              'That is what makes it weak.'
          )
        : verdict(
            'info',
            'The two columns differ at every round, so encrypting and decrypting really are different ' +
              'operations — the same circuit fed different subkeys.'
          )
    );
  }

  function showWeak(keyHex: string): void {
    clear(weakOutput);
    const parsed = parseKeyStrict(keyHex, { allowWeak: true });
    if (!parsed.ok) {
      append(weakOutput, verdict('fail', el('span', { class: 'code-chip', text: parsed.error.code }), ' ', parsed.error.message));
      return;
    }
    const key = parsed.value.key;
    const blockResult = parseHex(blockInput.value, 8);
    const block = blockResult.ok ? blockResult.value : randomBytes(8);
    const { once, twice } = doubleEncrypt(key, block);
    const returned = bytesEqual(twice, block);
    const report = inspectKey(key);
    const distinctSubkeys = new Set(keySchedule(key).subkeys.map(toHex)).size;

    append(
      weakOutput,
      kv([
        ['Key', el('span', { class: 'hexline', text: report.hex })],
        [
          'Class',
          report.keyClass === 'weak'
            ? pill('bad', 'WEAK')
            : report.keyClass === 'semi-weak'
              ? pill('warn', 'SEMI-WEAK')
              : pill('ok', 'ordinary'),
        ],
        ['C0 register', el('span', { class: 'hexline', text: `0x${report.c0.toString(16).padStart(7, '0')}` })],
        ['D0 register', el('span', { class: 'hexline', text: `0x${report.d0.toString(16).padStart(7, '0')}` })],
        ['Distinct subkeys', `${distinctSubkeys} of 16`],
        ['Plaintext', el('span', { class: 'hexline', text: toHex(block) })],
        ['E(P)', el('span', { class: 'hexline', text: toHex(once) })],
        ['E(E(P))', el('span', { class: 'hexline hex-hi', text: toHex(twice) })],
      ]),
      returned
        ? verdict(
            'alarm',
            el('strong', { text: 'E(E(P)) = P. ' }),
            weakKeyReason(key) ??
              'Encrypting twice returned the plaintext, so this key makes the cipher its own inverse.'
          )
        : verdict(
            'pass',
            el('strong', { text: 'E(E(P)) is not P. ' }),
            `This key produces ${distinctSubkeys} distinct subkeys, so the forward and reversed ` +
              'schedules differ and double encryption is not the identity — which is what an ' +
              'ordinary key should do.'
          )
    );
  }

  runBtn.addEventListener('click', runRoundTrip);
  randomBtn.addEventListener('click', () => {
    keyInput.value = toHex(fixParity(randomBytes(8)));
    runRoundTrip();
  });

  runRoundTrip();
}

function scheduleTable(forward: readonly string[], reverse: readonly string[]): HTMLElement {
  const body = el('tbody');
  for (let i = 0; i < 16; i++) {
    append(
      body,
      el(
        'tr',
        {},
        el('td', { text: String(i + 1) }),
        el('td', { text: forward[i] }),
        el('td', { text: reverse[i] }),
        el('td', {}, forward[i] === reverse[i] ? pill('bad', 'same') : pill('neutral', 'differs'))
      )
    );
  }
  return scroller(
    'Key schedule, forward and reversed',
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
          el('th', { scope: 'col', text: 'Round' }),
          el('th', { scope: 'col', text: 'Encrypt subkey' }),
          el('th', { scope: 'col', text: 'Decrypt subkey' }),
          el('th', { scope: 'col', text: 'Compared' })
        )
      ),
      body
    )
  );
}

function semiWeakTable(): HTMLElement {
  const body = el('tbody');
  for (const [a, b] of SEMI_WEAK_PAIRS) {
    const distinct = new Set(keySchedule(hexOf(a)).subkeys.map(toHex)).size;
    append(
      body,
      el(
        'tr',
        {},
        el('td', { text: a }),
        el('td', { text: b }),
        el('td', { text: `${distinct} of 16` })
      )
    );
  }
  return scroller(
    'Semi-weak key pairs',
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
          el('th', { scope: 'col', text: 'Key' }),
          el('th', { scope: 'col', text: 'Its partner' }),
          el('th', { scope: 'col', text: 'Distinct subkeys' })
        )
      ),
      body
    )
  );
}

function hexOf(text: string): Uint8Array {
  const parsed = parseHex(text, 8);
  if (!parsed.ok) throw new Error(`bad shipped constant: ${text}`);
  return parsed.value;
}

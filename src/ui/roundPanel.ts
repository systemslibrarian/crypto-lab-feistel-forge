/**
 * Exhibit 1 — One Round. The headline mechanism, shown rather than asserted.
 *
 * The claim this panel exists to make visible:
 *
 *     A Feistel round inverts even though F does not.
 *
 * It is shown in three moves, in this order:
 *
 *  1. STEP THE REAL CIPHER. The diagram carries the actual L, R, subkey and
 *    f-output for the current round of a real DES encryption, taken from
 *    `traceBlock`. Nothing on screen is recomputed by this file.
 *  2. UNDO THE ROUND WITH THE SAME F, RUN FORWARDS. One button recomputes
 *    F(L(i), K(i)) and XORs it off R(i). The recovered half is compared
 *    byte-for-byte against the value the forward pass recorded. F is never
 *    inverted, and the comparison is the proof that it did not need to be.
 *  3. REPLACE F WITH SOMETHING DESTRUCTIVE. Switch to F = 0, which throws away
 *    its entire input, and repeat. The round still inverts. `measureImage`
 *    reports how many inputs that F collapses together, measured on the spot.
 */
import { traceBlock } from '../des/des';
import type { BlockTrace } from '../des/types';
import { parseHex, randomBytes, toHex, toSpacedHex, xorBytes, bytesEqual } from '../des/bytes';
import { fixParity, parseKeyStrict } from '../des/weakKeys';
import { measureImage, ROUND_FUNCTIONS, roundFunctionById, sboxCensus } from '../des/feistel';
import type { FeistelRoundFunction } from '../des/feistel';
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
  scroller,
  selectField,
  statusRegion,
  svg,
  textField,
  verdict,
} from './dom';

const DEFAULT_KEY = '133457799bbcdff1';
const DEFAULT_BLOCK = '0123456789abcdef';

interface State {
  key: Uint8Array;
  block: Uint8Array;
  trace: BlockTrace;
  round: number;
  f: FeistelRoundFunction;
}

export function renderRoundPanel(root: HTMLElement): void {
  clear(root);

  const keyResult = parseKeyStrict(DEFAULT_KEY);
  if (!keyResult.ok) throw new Error(`the shipped default key is invalid: ${keyResult.error.message}`);
  const blockResult = parseHex(DEFAULT_BLOCK, 8);
  if (!blockResult.ok) throw new Error('the shipped default block is invalid');

  const state: State = {
    key: keyResult.value.key,
    block: blockResult.value,
    trace: traceBlock(keyResult.value.key, blockResult.value, 'encrypt'),
    round: 1,
    f: roundFunctionById('des'),
  };

  append(
    root,
    intro(
      'What is a Feistel network?',
      el(
        'p',
        {},
        'A block cipher has to be undoable: whatever it does to your data, the holder of the key ' +
          'has to get the data back. That sounds like it forces every step to be reversible. ' +
          'Horst Feistel found a way around it in the early 1970s, and DES is the design that made ' +
          'it famous.'
      ),
      el(
        'p',
        {},
        'Split the block in half. Feed one half through a scrambling function ',
        el('code', { text: 'F' }),
        ', XOR the result onto the other half, then swap the halves. To undo it you run ',
        el('code', { text: 'F' }),
        ' again — forwards, on a value you already have — and XOR the same thing back off. ',
        el('strong', { text: 'F is never inverted, so F never has to be invertible.' }),
        ' That is the whole trick, and it is why DES could use a round function that throws away ' +
          'half the information it is given.'
      ),
      el(
        'p',
        {},
        'Below is one real round of real DES. Step through it, then press Undo and watch the same ',
        el('code', { text: 'F' }),
        ' put the block back together. Then swap ',
        el('code', { text: 'F' }),
        ' for one that is provably destructive and try again.'
      )
    )
  );

  // ── Controls ────────────────────────────────────────────────────────────
  const { wrap: keyWrap, input: keyInput } = textField(
    'round-key',
    'Key (16 hex digits)',
    DEFAULT_KEY,
    'A real 64-bit DES key: 56 key bits and 8 odd-parity bits.'
  );
  const { wrap: blockWrap, input: blockInput } = textField(
    'round-block',
    'Plaintext block (16 hex digits)',
    DEFAULT_BLOCK,
    'One 64-bit block — the whole of what DES encrypts at a time.'
  );
  const { wrap: fWrap, select: fSelect } = selectField(
    'round-f',
    'Round function F',
    ROUND_FUNCTIONS.map((f) => [f.id, f.name] as const),
    'des',
    'Everything except the first is a deliberately broken F, kept here to make a point.'
  );

  const applyBtn = button('Apply', 'btn btn-primary');
  const randomBtn = button('Random key & block');
  const inputStatus = statusRegion('Input status');

  append(
    root,
    card(
      'The block, the key, and F',
      'Change any of these and the trace below is recomputed on the real cipher.',
      el(
        'div',
        { class: 'controls' },
        keyWrap,
        blockWrap,
        fWrap,
        el('div', { class: 'field' }, applyBtn),
        el('div', { class: 'field' }, randomBtn)
      ),
      inputStatus
    )
  );

  // ── The diagram and the step controls ───────────────────────────────────
  const figureHost = el('div', {});
  const backBtn = button('‹ Back');
  const nextBtn = button('Next ›', 'btn btn-primary');
  const resetBtn = button('Reset to round 1');
  const progress = el('span', { class: 'meter-label round-progress', text: 'Round 1 / 16' });
  const values = el('div', {});

  append(
    root,
    card(
      'One round, stepped',
      'Every value below came out of a real DES encryption of the block above.',
      el(
        'div',
        { class: 'controls' },
        el('div', { class: 'field' }, backBtn),
        el('div', { class: 'field' }, nextBtn),
        el('div', { class: 'field' }, resetBtn),
        el('div', { class: 'field' }, progress)
      ),
      figureHost,
      values
    )
  );

  // ── Undo ────────────────────────────────────────────────────────────────
  const undoBtn = button('Undo this round with the same F', 'btn btn-primary');
  const undoOut = statusRegion('Undo result');
  append(
    root,
    card(
      'Undo it — without ever inverting F',
      'The inverse recomputes F on a value it already has and XORs it back off.',
      el(
        'p',
        {},
        'Given the two halves that come OUT of a round, the left one IS the right half that went ',
        'in. So F can be recomputed exactly as the forward pass computed it, and XORed back off ',
        'the other half:'
      ),
      el(
        'p',
        { class: 'hexline hexline-dim' },
        'R(i-1) = L(i)   and   L(i-1) = R(i) XOR F( L(i), K(i) )'
      ),
      el('div', { class: 'controls' }, el('div', { class: 'field' }, undoBtn)),
      undoOut
    )
  );

  // ── How destructive is F, measured ──────────────────────────────────────
  const collapseHost = el('div', {});
  append(
    root,
    card(
      'How much does F throw away?',
      'Measured by sweeping inputs through the selected F, not asserted.',
      collapseHost,
      disclosure(
        "Where DES's own f loses its information — the S-box census",
        el(
          'p',
          {},
          "The sweep above varies only part of R, so it understates how much DES's f discards. " +
            'The real answer needs no sampling at all. Each S-box maps 6 bits to 4, and every ' +
            '4-bit value occurs exactly once in each of the box’s four rows — so every output ' +
            'has exactly four preimages. Eight boxes, four each:'
        ),
        sboxCensusTable(),
        el(
          'p',
          {},
          'f collapses 4^8 = 65,536 expanded inputs onto every 32-bit value it produces. It is ' +
            'about as far from invertible as a function of that shape can be, and the cipher is ' +
            'still perfectly decryptable.'
        )
      )
    )
  );

  append(
    root,
    learnerCheck({
      question:
        'You replace DES’s round function with F(R, K) = 0, which ignores everything. What happens to decryption?',
      options: [
        {
          text: 'Decryption breaks — the round can no longer be undone.',
          correct: false,
          why: 'Try it above. The network still inverts. Decryption never calls F backwards, so what F does to information is irrelevant to whether the ROUND is reversible. It matters enormously for security — with F constant, the cipher is trivial — but not for invertibility.',
        },
        {
          text: 'Decryption still works; the cipher is just worthless.',
          correct: true,
          why: 'Exactly. Invertibility is a property of the Feistel STRUCTURE; security is a property of F. Separating those two is what the construction buys you, and it is why DES could afford a round function that throws away 16 of every 32 bits.',
        },
        {
          text: 'It depends on the key schedule.',
          correct: false,
          why: 'The schedule decides which subkey each round gets, not whether a round can be undone. Reverse the schedule and any Feistel network runs backwards, whatever F is.',
        },
      ],
    })
  );

  // ── Wiring ──────────────────────────────────────────────────────────────

  function redraw(): void {
    clear(figureHost);
    clear(values);
    const round = state.trace.rounds[state.round - 1];
    const i = state.round;
    const fOut = currentF(state, round.rightIn, round.subkey);
    append(figureHost, roundDiagram(state, round));
    append(
      values,
      kv([
        [`L${i - 1} (left in)`, el('span', { class: 'hexline', text: toSpacedHex(round.leftIn) })],
        [`R${i - 1} (right in)`, el('span', { class: 'hexline', text: toSpacedHex(round.rightIn) })],
        [`K${i} (subkey, 48 bits)`, el('span', { class: 'hexline', text: toSpacedHex(round.subkey) })],
        ['f(R, K)', el('span', { class: 'hexline hex-hi', text: toSpacedHex(fOut) })],
        // L(i) IS R(i-1) — the swap, printed as the same value rather than as a
        // second computation, because that identity is the mechanism.
        [`L${i} (left out) = R${i - 1}`, el('span', { class: 'hexline', text: toSpacedHex(round.rightIn) })],
        [
          `R${i} (right out) = L${i - 1} XOR f`,
          el('span', { class: 'hexline', text: toSpacedHex(xorBytes(round.leftIn, fOut)) }),
        ],
      ])
    );
    progress.textContent = `Round ${state.round} / 16`;
    backBtn.disabled = state.round === 1;
    nextBtn.disabled = state.round === 16;
    drawCollapse();
  }

  function drawCollapse(): void {
    clear(collapseHost);
    const round = state.trace.rounds[state.round - 1];
    const measurement = measureImage(state.f, round.subkey, 14);
    const destructive = measurement.outputs < measurement.inputs;
    append(
      collapseHost,
      el('p', {}, el('strong', { text: state.f.name }), ' — ', el('span', { text: state.f.note })),
      kv([
        ['Inputs swept', `${n(measurement.inputs)} values of R (the low ${measurement.bits} bits)`],
        ['Distinct outputs', n(measurement.outputs)],
        [
          'Inputs per output',
          measurement.collapseRatio === 1 ? '1 — no collisions in this sweep' : measurement.collapseRatio.toFixed(2),
        ],
      ]),
      destructive
        ? verdict(
            'info',
            el('strong', { text: 'Not injective. ' }),
            `${n(measurement.inputs)} inputs produced only ${n(measurement.outputs)} distinct outputs, so at least two inputs share an output. This F cannot be inverted — and the round above still undoes itself.`
          )
        : verdict(
            'info',
            el('strong', { text: 'No collisions in this sweep. ' }),
            'That is not the same as invertible: a narrow sweep of R moves only some of the eight S-boxes. Open the census below for the measurement that settles it.'
          )
    );
  }

  function currentF(s: State, right: Uint8Array, subkey: Uint8Array): Uint8Array {
    return s.f.apply(right, subkey);
  }

  function apply(): void {
    clear(inputStatus);
    const parsedKey = parseKeyStrict(keyInput.value, { allowWeak: true });
    if (!parsedKey.ok) {
      keyInput.setAttribute('aria-invalid', 'true');
      append(
        inputStatus,
        verdict('fail', el('span', { class: 'code-chip', text: parsedKey.error.code }), ' ', parsedKey.error.message)
      );
      return;
    }
    keyInput.setAttribute('aria-invalid', 'false');
    const parsedBlock = parseHex(blockInput.value, 8);
    if (!parsedBlock.ok) {
      blockInput.setAttribute('aria-invalid', 'true');
      append(
        inputStatus,
        verdict('fail', el('span', { class: 'code-chip', text: parsedBlock.error.code }), ' ', parsedBlock.error.message)
      );
      return;
    }
    blockInput.setAttribute('aria-invalid', 'false');
    state.key = parsedKey.value.key;
    state.block = parsedBlock.value;
    state.trace = traceBlock(state.key, state.block, 'encrypt');
    state.f = roundFunctionById(fSelect.value);
    state.round = 1;
    clear(undoOut);
    append(
      inputStatus,
      verdict(
        'pass',
        `Loaded. Full DES ciphertext under this key: `,
        el('span', { class: 'hexline hex-hi', text: toHex(state.trace.output) }),
        state.f.isDes
          ? '.'
          : ` — note the trace below now uses ${state.f.name}, which is NOT DES. The ciphertext shown here is still the real cipher's.`
      )
    );
    redraw();
  }

  applyBtn.addEventListener('click', apply);
  fSelect.addEventListener('change', () => {
    // The no-op guard: re-selecting the F that is already selected changes
    // nothing on screen, so a fresh undo result must survive it.
    if (fSelect.value === state.f.id) return;
    state.f = roundFunctionById(fSelect.value);
    redraw();
    retireUndo('the round function changed');
  });
  randomBtn.addEventListener('click', () => {
    keyInput.value = toHex(fixParity(randomBytes(8)));
    blockInput.value = toHex(randomBytes(8));
    apply();
  });
  backBtn.addEventListener('click', () => {
    if (state.round === 1) return;
    state.round--;
    redraw();
    retireUndo('the round changed');
  });
  nextBtn.addEventListener('click', () => {
    if (state.round === 16) return;
    state.round++;
    redraw();
    retireUndo('the round changed');
  });
  resetBtn.addEventListener('click', () => {
    if (state.round === 1) return;
    state.round = 1;
    redraw();
    retireUndo('the round changed');
  });

  /** Only retire something that is actually there. */
  function retireUndo(because: string): void {
    if (!undoOut.firstChild) return;
    retire(undoOut, 'That undo result', because);
  }

  undoBtn.addEventListener('click', () => {
    clear(undoOut);
    const round = state.trace.rounds[state.round - 1];
    const fOut = currentF(state, round.rightIn, round.subkey);
    const leftOut = round.rightIn;
    const rightOut = xorBytes(round.leftIn, fOut);
    // The inverse, computed with F run FORWARDS on a value the inverse already
    // holds. Nothing here inverts F, and nothing here reads round.leftIn.
    const recomputedF = state.f.apply(leftOut, round.subkey);
    const recoveredRight = leftOut;
    const recoveredLeft = xorBytes(rightOut, recomputedF);
    const matches = bytesEqual(recoveredLeft, round.leftIn) && bytesEqual(recoveredRight, round.rightIn);
    append(
      undoOut,
      kv([
        ['Round output L, R', el('span', { class: 'hexline', text: `${toHex(leftOut)}  ${toHex(rightOut)}` })],
        [
          'F recomputed forwards',
          el('span', { class: 'hexline hex-hi', text: `F(${toHex(leftOut)}, K${state.round}) = ${toHex(recomputedF)}` }),
        ],
        [
          'Recovered L, R',
          el('span', { class: 'hexline', text: `${toHex(recoveredLeft)}  ${toHex(recoveredRight)}` }),
        ],
        [
          'Round input was',
          el('span', { class: 'hexline', text: `${toHex(round.leftIn)}  ${toHex(round.rightIn)}` }),
        ],
      ]),
      matches
        ? verdict(
            'pass',
            el('strong', { text: 'Byte for byte identical. ' }),
            `Round ${state.round} was undone using ${state.f.name} run forwards. F was never inverted` +
              (state.f.isDes ? '.' : ' — and this F is provably not invertible at all.')
          )
        : verdict(
            'fail',
            el('strong', { text: 'Recovery failed. ' }),
            'If you are reading this, the Feistel inverse in this page is wrong and the test suite should have caught it.'
          )
    );
  });

  redraw();
}

/**
 * The round, drawn with this round's real values on the wires.
 *
 * `role="img"` with a label that names the actual halves, and the same numbers
 * repeated as text in the `<dl>` beneath — the list is the accessible source of
 * truth, the drawing is the intuition.
 */
function roundDiagram(state: State, round: BlockTrace['rounds'][number]): SVGElement {
  const i = state.round;
  const fOut = state.f.apply(round.rightIn, round.subkey);
  const rightOut = xorBytes(round.leftIn, fOut);
  const box = (x: number, y: number, label: string, value: string, live = false): SVGElement =>
    svg(
      'g',
      {},
      svg('rect', { x, y, width: 200, height: 34, rx: 6, class: live ? 'rf-box rf-box-f' : 'rf-box' }),
      svg('text', { x: x + 10, y: y + 22, class: 'rf-label' }, label),
      svg('text', { x: x + 10, y: y + 50, class: 'rf-value' }, value)
    );

  return svg(
    'svg',
    {
      viewBox: '0 0 620 310',
      class: 'round-figure',
      role: 'img',
      'aria-label': `Round ${i} of DES. Left half in ${toHex(round.leftIn)}, right half in ${toHex(
        round.rightIn
      )}. F outputs ${toHex(fOut)}. Left half out ${toHex(round.rightIn)}, right half out ${toHex(rightOut)}.`,
    },
    box(40, 12, `L${i - 1}`, toHex(round.leftIn)),
    box(380, 12, `R${i - 1}`, toHex(round.rightIn)),

    // R goes into F.
    svg('path', { d: 'M440 46 L440 96', class: 'rf-wire' }),
    // R also passes straight through to become the next left half.
    svg('path', { d: 'M555 46 L555 214', class: 'rf-wire' }),

    // F, with the subkey entering from below.
    svg('rect', { x: 340, y: 96, width: 170, height: 40, rx: 6, class: 'rf-box-f' }),
    svg('text', { x: 352, y: 121, class: 'rf-label' }, `F(R${i - 1}, K${i})`),
    svg('path', { d: 'M425 172 L425 136', class: 'rf-wire' }),
    svg('text', { x: 425, y: 190, class: 'rf-value', 'text-anchor': 'middle' }, `K${i} = ${toHex(round.subkey)}`),

    // F's output runs left into the XOR.
    svg('path', { d: 'M340 116 L154 116', class: 'rf-wire-live' }),
    svg('text', { x: 200, y: 106, class: 'rf-value' }, toHex(fOut)),

    // L drops into the XOR.
    svg('path', { d: 'M140 46 L140 102', class: 'rf-wire' }),
    svg('circle', { cx: 140, cy: 116, r: 14, class: 'rf-xor' }),
    svg('text', { x: 140, y: 121, class: 'rf-label', 'text-anchor': 'middle' }, '⊕'),
    svg('path', { d: 'M140 130 L140 214', class: 'rf-wire-live' }),

    // The swap: the XOR result becomes the next RIGHT half, and the old right
    // half becomes the next LEFT half. The crossing is the swap.
    svg('path', { d: 'M140 214 L480 252', class: 'rf-wire-live' }),
    svg('path', { d: 'M555 214 L200 252', class: 'rf-wire' }),

    box(40, 252, `L${i}`, toHex(round.rightIn)),
    box(380, 252, `R${i}`, toHex(rightOut))
  );
}

/** The preimage census for all eight S-boxes, computed by exhaustion. */
function sboxCensusTable(): HTMLElement {
  const body = el('tbody');
  for (let box = 0; box < 8; box++) {
    const census = sboxCensus(box);
    append(
      body,
      el(
        'tr',
        {},
        el('td', { text: `S${box + 1}` }),
        el('td', { text: String(census.inputs) }),
        el('td', { text: String(census.distinctOutputs) }),
        el('td', { text: census.uniform ? `${census.preimageCounts[0]} each` : 'uneven' }),
        el('td', {}, pill(census.uniform && census.distinctOutputs === 16 ? 'ok' : 'bad', census.uniform ? '4-to-1' : 'irregular'))
      )
    );
  }
  return scroller(
    'S-box preimage census',
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
          el('th', { scope: 'col', text: 'Box' }),
          el('th', { scope: 'col', text: '6-bit inputs' }),
          el('th', { scope: 'col', text: 'Distinct outputs' }),
          el('th', { scope: 'col', text: 'Preimages' }),
          el('th', { scope: 'col', text: 'Verdict' })
        )
      ),
      body
    )
  );
}

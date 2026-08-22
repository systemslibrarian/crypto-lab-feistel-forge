/**
 * Small DOM helpers.
 *
 * Two accessibility rules are baked in here rather than left to each panel:
 *
 *  - `verdict()` always emits a glyph AND a word AND a tone. Nothing in this
 *    lab conveys state by colour alone, and centralising it means a new panel
 *    cannot forget (WCAG 1.4.1).
 *  - `scroller()` always attaches `role="region"`, `tabindex="0"` and a label,
 *    because an `overflow:auto` box a keyboard cannot reach is a 2.1.1 failure
 *    that only shows up on the CI runner.
 */

type Attrs = Record<string, string | number | boolean | undefined>;
type Child = Node | string | null | undefined | false;

/** Create an element with attributes and children. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key === 'class') node.className = String(value);
    else if (key === 'text') node.textContent = String(value);
    else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, String(value));
  }
  append(node, ...children);
  return node;
}

/** Create an SVG element — `document.createElement` produces the wrong namespace. */
export function svg(tag: string, attrs: Attrs = {}, ...children: (Node | string | null | false)[]): SVGElement {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    node.setAttribute(key, String(value));
  }
  for (const child of children) {
    if (!child) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function append(parent: Node, ...children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export type Tone = 'pass' | 'fail' | 'alarm' | 'info';

const GLYPH: Record<Tone, string> = { pass: '✓', fail: '✕', alarm: '!', info: 'i' };

/**
 * A verdict line: tone, glyph and words together.
 *
 * The glyph is `aria-hidden` because the words beside it already carry the
 * meaning; a screen reader announcing "check mark" adds nothing. Colour is the
 * third channel, never the only one.
 */
export function verdict(tone: Tone, ...body: Child[]): HTMLElement {
  return el(
    'p',
    { class: `verdict verdict-${tone}` },
    el('span', { class: 'verdict-glyph', 'aria-hidden': 'true', text: GLYPH[tone] }),
    el('span', { class: 'verdict-body' }, ...body)
  );
}

/** A live output region. Async results must announce themselves. */
export function statusRegion(label: string, className = ''): HTMLElement {
  return el('div', {
    class: className,
    role: 'status',
    'aria-live': 'polite',
    'aria-label': label,
  });
}

/** A horizontally or vertically scrolling box a keyboard can actually reach. */
export function scroller(label: string, className: string, ...children: Child[]): HTMLElement {
  return el('div', { class: className, role: 'region', tabindex: '0', 'aria-label': label }, ...children);
}

/** A definition list of labelled values. */
export function kv(pairs: readonly (readonly [string, Child])[]): HTMLElement {
  const list = el('dl', { class: 'kv' });
  for (const [term, value] of pairs) {
    append(list, el('dt', { text: term }), el('dd', {}, value));
  }
  return list;
}

/** A pill: tone plus a word. */
export function pill(kind: 'ok' | 'bad' | 'warn' | 'neutral', text: string): HTMLElement {
  return el('span', { class: `pill pill-${kind}`, text });
}

/** A card with a heading. */
export function card(title: string, note?: string, ...children: Child[]): HTMLElement {
  const head = el('div', { class: 'card-title' }, el('h3', { text: title }));
  if (note) append(head, el('span', { class: 'card-note', text: note }));
  return el('section', { class: 'card' }, head, ...children);
}

/** The plain-language on-ramp every exhibit opens with. */
export function intro(title: string, ...paragraphs: Child[]): HTMLElement {
  return el('section', { class: 'intro' }, el('h2', { text: title }), ...paragraphs);
}

/** A labelled text input. */
export function textField(
  id: string,
  label: string,
  value: string,
  help?: string
): { wrap: HTMLElement; input: HTMLInputElement } {
  const input = el('input', { type: 'text', id, value, spellcheck: 'false', autocomplete: 'off' });
  const wrap = el(
    'div',
    { class: 'field' },
    el('label', { class: 'field-label', for: id, text: label }),
    input,
    help ? el('span', { class: 'field-help', text: help }) : null
  );
  return { wrap, input };
}

/** A labelled select. */
export function selectField(
  id: string,
  label: string,
  options: readonly (readonly [string, string])[],
  selected: string,
  help?: string
): { wrap: HTMLElement; select: HTMLSelectElement } {
  const select = el('select', { id });
  for (const [value, text] of options) {
    append(select, el('option', { value, text, selected: value === selected }));
  }
  const wrap = el(
    'div',
    { class: 'field' },
    el('label', { class: 'field-label', for: id, text: label }),
    select,
    help ? el('span', { class: 'field-help', text: help }) : null
  );
  return { wrap, select };
}

/** A labelled range slider with a live readout of its own value. */
export function rangeField(
  id: string,
  label: string,
  attrs: { min: number; max: number; step: number; value: number },
  format: (value: number) => string
): { wrap: HTMLElement; input: HTMLInputElement; readout: HTMLElement } {
  const input = el('input', {
    type: 'range',
    id,
    min: attrs.min,
    max: attrs.max,
    step: attrs.step,
    value: attrs.value,
  });
  const readout = el('span', { class: 'field-help', text: format(attrs.value) });
  input.addEventListener('input', () => {
    readout.textContent = format(Number(input.value));
  });
  const wrap = el(
    'div',
    { class: 'field' },
    el('label', { class: 'field-label', for: id, text: label }),
    input,
    readout
  );
  return { wrap, input, readout };
}

/**
 * A button.
 *
 * `className` REPLACES the default, so a variant must name its base too —
 * `'btn btn-primary'`, not `'btn-primary'`. `.btn-primary` and `.btn-danger`
 * set only their colours and lean on `.btn` for everything else; passing the
 * variant alone leaves the UA's own `buttonface` background in place, which in
 * a dark colour-scheme is rgb(107,107,107) and fails contrast against every
 * ink in this palette. The a11y gate caught exactly that on `.btn-danger`.
 *
 * `.seg-btn` and `.check-opt` are self-contained and are passed alone.
 */
export function button(text: string, className = 'btn', attrs: Attrs = {}): HTMLButtonElement {
  return el('button', { type: 'button', class: className, ...attrs }, text);
}

/** A disclosure that ships SHUT — the state every reader arrives at. */
export function disclosure(summaryText: string, ...children: Child[]): HTMLDetailsElement {
  return el(
    'details',
    {},
    el('summary', { text: summaryText }),
    el('div', { class: 'details-body' }, ...children)
  ) as HTMLDetailsElement;
}

export interface LearnerCheck {
  readonly question: string;
  readonly options: readonly { readonly text: string; readonly correct: boolean; readonly why: string }[];
}

/**
 * A question with real answers.
 *
 * Shipped inside a shut disclosure so it never competes with the exhibit, and
 * every option explains itself once chosen — a wrong answer that only says
 * "wrong" teaches nothing.
 */
export function learnerCheck(check: LearnerCheck): HTMLDetailsElement {
  // `.check-result` exists so a test can name THIS pill rather than every pill
  // on the panel — the S-box census alone renders eight of them.
  const result = statusRegion('Learner check result', 'check-result');
  const options = el('div', { class: 'check-opts' });
  for (const option of check.options) {
    const btn = button(option.text, 'check-opt');
    btn.addEventListener('click', () => {
      clear(result);
      append(
        result,
        el(
          'p',
          {},
          pill(option.correct ? 'ok' : 'bad', option.correct ? 'Correct' : 'Not quite'),
          ' ',
          el('span', { text: option.why })
        )
      );
    });
    append(options, btn);
  }
  return disclosure('Check yourself', el('p', { text: check.question }), options, result);
}

/**
 * Replace a stale result with a notice saying it was retired.
 *
 * A verdict that stays on screen after its inputs change is the most ordinary
 * way a demo tells a lie: the numbers beside it no longer describe the numbers
 * above it, and nothing says so. Every control in this lab whose change
 * invalidates a printed result calls this instead of silently clearing, so the
 * page states what happened rather than leaving a gap the reader has to notice.
 *
 * Callers guard for no-ops themselves — re-selecting the value that is already
 * selected must NOT retire a fresh result, and `e2e/claims.spec.ts` asserts
 * both halves of that.
 */
export function retire(region: HTMLElement, what: string, because: string): void {
  clear(region);
  const notice = verdict(
    'info',
    el('strong', { text: 'Retired. ' }),
    `${what} no longer matches the inputs on screen — ${because}. Run it again.`
  );
  notice.classList.add('retired');
  append(region, notice);
}

/** Format a number with thousands separators, for counts on screen. */
export function n(value: number): string {
  return Math.round(value).toLocaleString('en-US');
}

/** Format a power of two as `2^k`, with a decimal gloss for readability. */
export function pow2(exponent: number): string {
  const approx = 2 ** exponent;
  if (approx < 1e6) return `2^${exponent} (${n(approx)})`;
  return `2^${exponent} (${approx.toExponential(2).replace('e+', ' × 10^')})`;
}

/** Format a byte count in the largest unit that keeps it readable. */
export function bytes(count: number): string {
  const units = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
  let value = count;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${unit === 0 ? n(value) : value.toFixed(value < 10 ? 2 : 1)} ${units[unit]}`;
}

/** Format a duration in the largest unit that keeps it readable. */
export function duration(seconds: number): string {
  if (!Number.isFinite(seconds)) return 'unbounded';
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 90) return `${seconds.toFixed(1)} s`;
  if (seconds < 5400) return `${(seconds / 60).toFixed(1)} minutes`;
  if (seconds < 172800) return `${(seconds / 3600).toFixed(1)} hours`;
  if (seconds < 3.15e9) return `${(seconds / 86400).toFixed(1)} days`;
  return `${n(seconds / 3.156e7)} years`;
}

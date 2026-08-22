import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the
 * retired fleet gate did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising
 *     it, so the rendering a reduced-motion reader actually gets — `.panel`
 *     with its `panel-in` animation cancelled by the stylesheet's own rule —
 *     was never once the rendering that got scanned. This gate sets the
 *     preference through `emulateMedia`, asserts from inside the page that it
 *     took effect (`test.use({ reducedMotion })` silently does nothing on
 *     Playwright 1.61.x), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` puts all six tabpanels on screen AT ONCE — a
 *     rendering no reader can reach — and script-opening the disclosures means
 *     the SHUT state, which is what every reader arrives at, was never scanned
 *     at all. This gate switches tabs by clicking them and opens each
 *     disclosure through its `<summary>`, which is the route a reader has, and
 *     scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms per tab, and scanned ONCE at the
 *     end. In this lab that would have discarded every state worth scanning:
 *     the PARITY_INVALID and WEAK_KEY failure verdicts, the weak-key alarm, the
 *     complementation search that finds nothing, the meet-in-the-middle
 *     recovery, the Sweet32 recovery and its deliberately-wrong twin, and the
 *     BLOCK_SIZE_EXCEEDED refusal — none of which is reachable without typing
 *     or choosing something specific on purpose. This drive names every control
 *     it touches, asserts a real completion signal after each, and scans after
 *     every step, at 1280 and at 380.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things hide from
 *     it here: the shared top bar's `color-mix()` ink and boundary, which axe
 *     files under `incomplete` rather than judging, and an `aria-label` on a
 *     role-less element, which axe reports only as `aria-prohibited-attr` in
 *     that same bucket. This page depends on getting the second right — every
 *     live output is a `role="status"` with an `aria-label`, and every scroller
 *     is a `role="region"` with one.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     composited backdrops, to every `.btn`, `.seg-btn`, `.tab-btn` and
 *     `.check-opt`, and to all states past first paint. `nontext.ts` replaces
 *     it with a measured oracle over every control at every driven state, and
 *     `expectNoHorizontalOverflow` adds the 1.4.10 check axe has no rule for —
 *     which matters here, where a 16-digit hex run and a five-column table live
 *     on every panel.
 */
/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels `.panel` / `.reveal` animations and every transition, so
 * `getAnimations()` is normally empty and this returns on the sixth frame. It
 * stays because the shared top bar's `.cl-btn` transitions are declared
 * OUTSIDE the lab's `@media` block — `* { transition: none !important }` wins
 * today, but that is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * has that shape in miniature: `@keyframes panel-in` starts
 * `from { opacity: 0 }` and every `.panel` rides it. The reduced-motion block
 * cancels it with `animation: none`, which restores the static `opacity: 1` —
 * correct today, and this assertion is what makes that a measurement rather
 * than a reading of the stylesheet.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is the decorative
 * verdict glyphs beside their own words — see `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's own
 * hero is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies
 * a second banner today — but the shared bar's `dedupeBanner()` exists because
 * other labs in this fleet DID ship one, and the hero markup is the part of
 * this page most likely to be re-templated from a lab that uses `<header>`.
 * Asserting the OUTCOME rather than the markup is what catches that edit.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * This lab's one list is the Sweet32 exhibit's CBC block stream: a flex row of
 * `div.strip-block` children given an explicit `role="list"` / `role="listitem"`
 * pair, because a `<ul>` styled `display: flex; list-style: none` is exactly
 * the declaration that makes Safari and VoiceOver DROP the list's implicit
 * role. So here, unlike most of this fleet, an explicit list role is the fix
 * rather than the defect.
 *
 * What is asserted is therefore the SHAPE of that fix, over ANY element rather
 * than just `ul`/`ol`: an explicit role on something that reads as a list must
 * be `list` (any other value orphans every item under it), and a `role="list"`
 * must never sit on an EMPTY element, because axe applies
 * `aria-required-children` to the explicit role and fails it the day the stream
 * renders with no blocks. Roles are assigned as attributes by an
 * element-creation helper, so ask the DOM rather than grepping the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role], [role=list]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);

  // Every listitem must have a list parent, or axe reports it orphaned.
  const orphans = await page.$$eval('[role=listitem]', (els) =>
    els
      .filter((e) => e.parentElement?.getAttribute('role') !== 'list')
      .map((e) => `${e.tagName.toLowerCase()}.${(e.getAttribute('class') ?? '').trim()}`)
  );
  expect(orphans, 'role="listitem" outside a role="list" parent').toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Nothing in this lab's JS branches on
 * `matchMedia`, but the CSS reduced-motion block is the only thing standing
 * between a scan and the mid-flight `panel-in` opacity, so the assertion is the
 * difference between scanning the reduced-motion rendering and believing we did.
 *
 * The theme seed is deliberately WRONG. Dark is the only theme here and
 * `index.html` pins it before first paint while overwriting whatever a visitor
 * stored back when the header carried a toggle. Seeding `localStorage.theme =
 * 'light'` and then asserting `data-theme="dark"` is what turns that sentence
 * into a measurement: if the anti-flash script ever started READING the stored
 * value instead of writing it, this boot fails rather than quietly scanning a
 * theme the lab does not ship.
 *
 * The defaults are asserted at length because `main.ts` renders each tabpanel
 * lazily on first activation, and the Round panel steps a real DES encryption
 * at mount. A navigation that resolves proves nothing: a renderer that threw
 * would leave `#panel-round` empty, and an empty region is exactly what a scan
 * reports as perfectly accessible.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript(() => localStorage.setItem('theme', 'light'));
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  // Dark regardless of what was stored. `theme` is the parameter the spec
  // labels its runs with; this lab has exactly one.
  expect(theme).toBe('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('dark');
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('.tab-btn')).toHaveCount(6);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all —
  // not the shared bar's, which was removed, and not a lab-local one. The
  // shared CSS hides any lab toggle with `display:none !important`, which would
  // leave a dead-but-known element; asserting the count at zero catches the day
  // one is added without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);

  // ── The arrival state: One Round active and already stepped ─────────────
  // `renderRoundPanel` traces a real DES encryption at mount, so first paint
  // includes the diagram, the six-row value list and the collapse measurement.
  // The other five panels are lazily rendered: hidden AND EMPTY until their tab
  // is first activated — asserted, because "empty" is this lab's tell that a
  // renderer threw (see `watchPageErrors`).
  await expect(page.locator('#panel-round .round-progress')).toHaveText('Round 1 / 16');
  await expect(page.locator('#panel-round svg.round-figure')).toHaveCount(1);
  await expect(page.locator('#panel-round .kv dd')).toHaveCount(9);
  for (const id of ['circuit', 'complement', 'mitm', 'sweet32', 'vectors']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }

  // ── Every shipped control default ───────────────────────────────────────
  await expect(page.locator('#round-key')).toHaveValue('133457799bbcdff1');
  await expect(page.locator('#round-block')).toHaveValue('0123456789abcdef');
  await expect(page.locator('#round-f')).toHaveValue('des');
  await expect(page.getByRole('button', { name: '‹ Back' })).toBeDisabled();

  // ── Disclosures ship shut ───────────────────────────────────────────────
  // The S-box census and the learner check both arrive closed; the gate this
  // replaces opened every one from script before its only scan.
  await expect(page.locator('#panel-round details[open]')).toHaveCount(0);
  await expect(page.locator('#panel-round details')).toHaveCount(2);

  await settle(page);
  await expectNotBlank(page, 'first paint');
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page has
 * three shapes that break it if nobody is looking: 16-digit hex runs in every
 * `.hexline` and `.kv dd` (which rely on `overflow-wrap: anywhere` rather than
 * a scroller), the five-column tables (which live inside `.table-scroll` and so
 * must not push the DOCUMENT sideways), and the CBC block strip (a flex row
 * inside `.strip`, whose 8.5rem minimum block width would otherwise widen the
 * page at 380px). The `.kv` grid also collapses to one column at 520px. At
 * 380px this check is what says all of that actually worked.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab has real scrollers and they carry content: `.table-scroll` holds
 * the key-schedule comparison, the S-box census, the semi-weak pairs, the MITM
 * candidate list and all six CAVP vector families, and `.strip` holds the CBC
 * block stream. Every one is emitted by `scroller()` in `src/ui/dom.ts`, which
 * attaches `role="region"`, `tabindex="0"` and a label together so a new one
 * cannot be born without a keyboard route. This assertion is what makes that a
 * measurement — and it fails on the Linux CI runner even where it passes on a
 * local Chromium, which is exactly why it runs at every driven state.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because the shared top bar's
 *    ink and its whole control boundary are `color-mix()` values axe declines
 *    to resolve. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides. This page leans on getting that
 *    right: every live output is a `role="status"` carrying an `aria-label`,
 *    every scroller a `role="region"` carrying one, and the round diagram an
 *    `<svg role="img">` whose label names the halves it draws. Drop any of
 *    those roles and the label is silently discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s
  // (the shared actions and the tablist wrapper), one `<main>` and a footer.
  // `landmark-complementary-is-top-level` is the live one: the hero aside is a
  // child of `#app`, not of a section, which is what keeps it passing.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Switch to a tab by clicking it, and prove the switch happened. */
async function openTab(page: Page, name: RegExp, panelId: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(panelId)).toBeVisible();
  await expect(page.locator(panelId)).not.toBeEmpty();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: One
 *    Round active and already stepped through a real DES encryption, five
 *    panels hidden and unrendered, every disclosure shut. The gate this
 *    replaces force-revealed all of it before its only scan.
 *
 *  - EVERY PANEL IS RENDERED LAZILY, so a tab that is never clicked is a panel
 *    that is never even IN the DOM. Each of the six is activated through its
 *    real tab button and scanned in its own driven states.
 *
 *  - EVERY FAILURE AND ALARM STATE. This lab's whole subject is things going
 *    wrong, and none of those renderings is reachable without choosing
 *    something specific: PARITY_INVALID and WEAK_KEY behind their code chips,
 *    the weak-key `E(E(P)) = P` alarm, the complementation search that sweeps
 *    the whole space and finds nothing, the recovered 2DES key pair, the
 *    recovered session cookie, the same arithmetic producing garbage on a
 *    non-colliding pair, and the BLOCK_SIZE_EXCEEDED refusal. Every one is
 *    driven and scanned.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the
 *    state a reader occupies the instant after pressing a button — and
 *    `.tab-btn:hover`, `.btn:hover` and `.cl-btn:hover` all repaint. Scanned
 *    explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a
 *    verdict appearing, a code chip's text, a round counter, `aria-selected`.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: One Round stepped, five panels unrendered, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── One Round ───────────────────────────────────────────────────────────
  await page.getByRole('button', { name: /Undo this round/ }).click();
  await expect(page.locator('#panel-round .verdict-pass')).toContainText('Byte for byte identical');
  await scanAt('Round: the round undone with DES f run forwards — pass verdict');

  // The destructive F. The collapse card must change its wording, and the undo
  // must still succeed — that pairing IS the exhibit's claim.
  await page.selectOption('#round-f', 'zero');
  await expect(page.locator('#panel-round .verdict-info')).toContainText('Not injective');
  await scanAt('Round: F = 0 selected — the measured collapse says not injective');

  await page.getByRole('button', { name: /Undo this round/ }).click();
  await expect(page.locator('#panel-round .verdict-pass')).toContainText('never inverted');
  await scanAt('Round: a provably non-invertible F, and the round still undone');

  await page.selectOption('#round-f', 'nibble');
  await expect(page.locator('#panel-round .verdict-info')).toContainText('Not injective');
  await page.selectOption('#round-f', 'des');

  // Stepping, including both disabled boundary states.
  for (const step of [2, 3]) {
    await page.getByRole('button', { name: 'Next ›' }).click();
    await expect(page.locator('#panel-round .round-progress')).toHaveText(`Round ${step} / 16`);
  }
  await expect(page.getByRole('button', { name: '‹ Back' })).toBeEnabled();
  await scanAt('Round: stepped to round 3, Back now enabled');

  await page.getByRole('button', { name: 'Reset to round 1' }).click();
  await expect(page.locator('#panel-round .round-progress')).toHaveText('Round 1 / 16');

  // A malformed key: the panel is only re-validated on Apply, so the click is
  // what paints `aria-invalid` and the code chip.
  await page.fill('#round-key', '0000010101010101');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.locator('#round-key')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#panel-round .code-chip')).toHaveText('PARITY_INVALID');
  await scanAt('Round: PARITY_INVALID — aria-invalid boundary and the failure verdict');

  await page.fill('#round-key', '133457799bbcdff1');
  await page.fill('#round-block', 'zz');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.locator('#panel-round .code-chip')).toHaveText('INPUT_NOT_HEX');
  await scanAt('Round: INPUT_NOT_HEX on the block field');

  await page.getByRole('button', { name: 'Random key & block' }).click();
  await expect(page.locator('#panel-round .verdict-pass')).toContainText('Loaded');
  await expect(page.locator('#round-key')).toHaveAttribute('aria-invalid', 'false');
  await scanAt('Round: a random key and block loaded, still hovered');

  // The disclosures, opened through their summaries.
  await page
    .locator('#panel-round details', { hasText: 'S-box census' })
    .locator('summary')
    .click();
  await expect(page.locator('#panel-round details[open]')).toHaveCount(1);
  await scanAt('Round: the S-box preimage census table open');

  await page
    .locator('#panel-round details', { hasText: 'Check yourself' })
    .locator('summary')
    .click();
  await page.locator('#panel-round .check-opt').first().click();
  await expect(page.locator('#panel-round .check-result .pill-bad')).toContainText('Not quite');
  await scanAt('Round: learner check answered wrong — the Not quite pill');

  await page.locator('#panel-round .check-opt').nth(1).click();
  await expect(page.locator('#panel-round .check-result .pill-ok')).toContainText('Correct');
  await scanAt('Round: learner check answered right — the Correct pill');

  // ── Same Circuit Both Ways ──────────────────────────────────────────────
  await openTab(page, /Same Circuit Both Ways/, '#panel-circuit');
  await expect(page.locator('#panel-circuit .verdict-pass')).toContainText('Recovered, byte for byte');
  await scanAt('Circuit: the healthy round trip and the two schedules side by side');

  await page.locator('#panel-circuit .seg-btn').first().click();
  await expect(page.locator('#panel-circuit .verdict-alarm')).toContainText('E(E(P)) = P');
  await scanAt('Circuit: a weak key — encryption is its own inverse, alarm verdict');

  await page.locator('#panel-circuit .seg-btn').last().click();
  await expect(page.locator('#panel-circuit .verdict-pass').last()).toContainText('E(E(P)) is not P');
  await scanAt('Circuit: an ordinary key for contrast');

  // The refusal, then the deliberately-broken mode that lifts it.
  await page.fill('#circuit-key', '0101010101010101');
  await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();
  await expect(page.locator('#panel-circuit .code-chip')).toHaveText('WEAK_KEY');
  await scanAt('Circuit: WEAK_KEY refusal on the default policy');

  await page.check('#circuit-allow-weak');
  await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();
  await expect(page.locator('#panel-circuit .verdict-alarm')).toContainText('same list');
  await scanAt('Circuit: deliberately-broken mode — the two schedules are identical');

  await page.fill('#circuit-key', '01fe01fe01fe01fe');
  await page.uncheck('#circuit-allow-weak');
  await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();
  await expect(page.locator('#panel-circuit .code-chip')).toHaveText('SEMI_WEAK_KEY');
  await scanAt('Circuit: SEMI_WEAK_KEY refusal, naming the partner key');

  // Named by its summary text, not by position: this panel ships two
  // disclosures and a positional locator silently opens whichever one moves.
  await page
    .locator('#panel-circuit details', { hasText: 'Semi-weak keys' })
    .locator('summary')
    .click();
  await expect(page.locator('#panel-circuit details[open]')).toHaveCount(1);
  await scanAt('Circuit: the semi-weak pairs table open');

  await page.getByRole('button', { name: 'Random healthy key' }).click();
  await expect(page.locator('#panel-circuit .verdict-pass').first()).toBeVisible();

  // ── Complementation ─────────────────────────────────────────────────────
  await openTab(page, /Complementation/, '#panel-complement');
  await expect(page.locator('#panel-complement .verdict-pass')).toContainText('agree, byte for byte');
  await scanAt('Complement: both sides computed and compared');

  await expect(page.locator('#panel-complement .verdict-info')).toContainText('twice the coverage');
  await scanAt('Complement: the race with the key inside the swept space');

  await page.selectOption('#comp-half', 'complement');
  await page.getByRole('button', { name: 'Race the two searches' }).click();
  await expect(page.locator('#panel-complement .verdict-alarm')).toContainText('missed it entirely');
  await expect(page.locator('#panel-complement .pill-bad')).toBeVisible();
  await scanAt('Complement: the plain search sweeps the whole space and finds nothing');

  await page
    .locator('#panel-complement details', { hasText: 'Why the second check works' })
    .locator('summary')
    .click();
  await expect(page.locator('#panel-complement details[open]')).toHaveCount(1);
  await scanAt('Complement: the derivation disclosure open');

  await page.fill('#comp-key', 'not-a-key');
  await page.getByRole('button', { name: 'Compute both sides' }).click();
  await expect(page.locator('#panel-complement .code-chip')).toHaveText('INPUT_NOT_HEX');
  await scanAt('Complement: INPUT_NOT_HEX on the key field');

  // ── 2DES meet-in-the-middle ─────────────────────────────────────────────
  await openTab(page, /Meet-in-the-Middle/, '#panel-mitm');
  await scanAt('MITM: the victim setup, before any search');

  await page.selectOption('#mitm-bits', '10');
  await page.getByRole('button', { name: 'Run the attack' }).click();
  await expect(page.locator('#panel-mitm .verdict-alarm')).toContainText('Both keys recovered', {
    timeout: 120_000,
  });
  await expect(page.locator('#panel-mitm .verdict-info')).toContainText('not the state of the art');
  await scanAt('MITM: both keys recovered, with the full-size projection beside it');

  await page
    .locator('#panel-mitm details', { hasText: 'What 3DES did about it' })
    .locator('summary')
    .click();
  await expect(page.locator('#panel-mitm details[open]')).toHaveCount(1);
  await scanAt('MITM: the "what 3DES did about it" disclosure open');

  // ── Sweet32 ─────────────────────────────────────────────────────────────
  await openTab(page, /Sweet32/, '#panel-sweet32');
  await expect(page.locator('#panel-sweet32 .arranged-banner')).toContainText('ARRANGED COLLISION');
  await scanAt('Sweet32: arrival — the birthday readout at 2^32 and the arranged banner');

  await page.locator('#sw-blocks').fill('14');
  await expect(page.locator('#panel-sweet32 .pill-ok').first()).toBeVisible();
  await scanAt('Sweet32: the slider at 2^14 blocks — both block sizes safe');

  await page.locator('#sw-blocks').fill('34');
  await expect(page.locator('#panel-sweet32 .pill-bad').first()).toBeVisible();
  await scanAt('Sweet32: the slider past the bound — the 64-bit row leaking');

  await page.selectOption('#sw-width', '12');
  await page.selectOption('#sw-trials', '8');
  await page.getByRole('button', { name: 'Measure it' }).click();
  await expect(page.locator('#panel-sweet32 .verdict-alarm').first()).toContainText(
    'truncated collision reveals nothing',
    { timeout: 120_000 }
  );
  await scanAt('Sweet32: the birthday curve measured on real DES-CBC output');

  await page.getByRole('button', { name: 'Recover the cookie' }).click();
  await expect(page.locator('#panel-sweet32 .verdict-alarm').last()).toContainText('The cookie is out');
  await scanAt('Sweet32: the session cookie lifted out of the ciphertext');

  await page.getByRole('button', { name: /did NOT collide/ }).click();
  await expect(page.locator('#panel-sweet32 .verdict-info').last()).toContainText('Garbage, as it should be');
  await scanAt('Sweet32: the same arithmetic on a non-colliding pair — garbage');

  await page.getByRole('button', { name: 'New session' }).click();
  await expect(page.locator('#panel-sweet32 .strip-block')).toHaveCount(10);

  await page.locator('#sw-limit-blocks').fill('26');
  await expect(page.locator('#panel-sweet32 .code-chip')).toHaveText('BLOCK_SIZE_EXCEEDED');
  await scanAt('Sweet32: BLOCK_SIZE_EXCEEDED — the meter over the SP 800-67 limit');

  await page.selectOption('#sw-limit-policy', 'none');
  await expect(page.locator('#panel-sweet32 .verdict-pass').last()).toContainText('Permitted');
  await scanAt('Sweet32: the deliberately-unbounded policy permitting the same session');

  await page
    .locator('#panel-sweet32 details', { hasText: 'does NOT claim' })
    .locator('summary')
    .click();
  await expect(page.locator('#panel-sweet32 details[open]')).toHaveCount(1);
  await scanAt('Sweet32: the "what this lab does NOT claim" disclosure open');

  // ── CAVP vectors ────────────────────────────────────────────────────────
  await openTab(page, /CAVP Vectors/, '#panel-vectors');
  await expect(page.locator('#panel-vectors .verdict-pass')).toContainText('Every published answer matched');
  await expect(page.locator('#panel-vectors .pill-ok').first()).toContainText('598 / 598');
  await scanAt('Vectors: all six families shut, the summary pill green');

  // The smallest family, opened — 19 rows rather than the 64-row sweeps, so the
  // contrast walk stays proportionate while still measuring an open table.
  await page.locator('#panel-vectors details[data-group="subtab"] > summary').click();
  await expect(page.locator('#panel-vectors details[open]')).toHaveCount(1);
  await scanAt('Vectors: the Substitution Table family expanded to its 19 rows');

  await page
    .locator('#panel-vectors details', { hasText: 'five known-answer families' })
    .locator('summary')
    .click();
  await scanAt('Vectors: the provenance disclosure open');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.getByRole('button', { name: 'Run all vectors again' }).hover();
  await scanAt('a primary button hovered');

  await page.getByRole('tab', { name: /One Round/ }).hover();
  await scanAt('an inactive tab hovered — its surface-3 fill repainted');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.getByRole('tab', { name: /CAVP Vectors/ }).focus();
  await scanAt('the active tab focused');

  await openTab(page, /One Round/, '#panel-round');
  await page.locator('#round-key').focus();
  await expect(page.locator('#round-key')).toBeFocused();
  await scanAt('a text input focused, showing its focus-visible outline');

  await page.locator('#round-f').focus();
  await scanAt('the styled select focused');
}

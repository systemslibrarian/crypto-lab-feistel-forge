import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where One
 * Round has already traced a real DES encryption and the other five tabpanels
 * are hidden and UNRENDERED; the shared skip link focused; a Feistel round
 * undone with DES's own f and then with an F that is provably not injective;
 * the round stepper at its two disabled boundaries; PARITY_INVALID and
 * INPUT_NOT_HEX behind their code chips and an `aria-invalid` boundary; the
 * S-box census and both learner-check answers opened through their summaries;
 * the healthy encrypt/decrypt round trip beside the two key schedules; a weak
 * key making encryption its own inverse; the WEAK_KEY and SEMI_WEAK_KEY
 * refusals and the deliberately-broken mode that lifts them; the
 * complementation identity computed on both sides; the brute-force race in
 * both halves, including the one where the plain search sweeps the entire
 * space and finds nothing; the meet-in-the-middle attack recovering both 2DES
 * keys with its full-size projection; the Sweet32 birthday readout at three
 * session sizes; the birthday curve measured on real DES-CBC output; the
 * session cookie lifted out of a ciphertext collision; the same arithmetic
 * producing garbage on a pair that did not collide; BLOCK_SIZE_EXCEEDED and
 * the unbounded policy that permits the same session; all 598 CAVP assertions
 * with one vector family expanded; three hover states and three focus rings.
 * Every one of those states is scanned, at desktop and at phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (the old gate's
 * `addStyleTag` motion kill bypassed the stylesheet's own reduced-motion
 * block, so the rendering reduced-motion readers get was never the one
 * scanned), why no panel is revealed from script (the old gate stripped every
 * `[hidden]` and opened every `<details>` by JS before its only scan), why the
 * lab's defaults are asserted rather than assumed, and why `violations` is not
 * the whole oracle.
 *
 * Dark is the only theme this lab ships, so there is one theme loop rather than
 * two — and `boot` seeds `localStorage.theme = 'light'` on purpose, so that the
 * "pinned dark regardless of what was stored" claim is measured rather than
 * described.
 */
for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}

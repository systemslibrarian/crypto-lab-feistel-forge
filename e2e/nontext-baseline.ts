/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, AND THAT IS THE POINT — this is the terminal state of the
 * ratchet, not an unrun check. Two decisions in `src/style.css` are what keep
 * it empty, and both were made because of this oracle rather than discovered by
 * it afterwards:
 *
 *  - TWO SEPARATE EDGE TOKENS. `--border` (#38435a) is decorative only — card
 *    edges, table rules, the footer line — and sits at 1.36–1.92:1 against the
 *    surfaces around it, which is fine for a divider and disqualifying for a
 *    control. Every control instead takes `--control-edge` (#808fae), which
 *    measures 4.14–5.85:1 against every surface in the palette. Nothing in the
 *    stylesheet paints a control boundary from `--border`.
 *  - AN ACCENT-FILLED CONTROL DOES NOT REPAINT ITS BORDER IN ITS OWN FILL.
 *    `.btn-primary` fills with `--accent` and edges with `--accent-dim`, so it
 *    has a real boundary as well as a fill; the fleet's usual failure here is a
 *    button whose border is the same colour as the fill it sits on, leaving no
 *    edge at all.
 *
 * The shared top bar's `.cl-btn` is the other entry most of this fleet carries,
 * baselined elsewhere at ~1.49:1 because its border mixes the PAGE's accent
 * toward transparent — unreachable at any mix percentage for a dark accent.
 * This lab ships the corrected form (border mixed from `--cl-ink`, which is
 * already mixed toward the bar's near-white ink and is therefore
 * accent-independent), adapted from `crypto-lab-schnorr-forge`.
 *
 * A run with `NT_BASELINE_CAPTURE=1` set prints every finding through this
 * same path and asserts nothing, which is how this file is regenerated.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};

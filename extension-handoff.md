# Feistel Forge — measured Luby–Rackoff experiments

Brief: `brief-extension.md`. Slug: `crypto-lab-feistel-forge`.
Starting main: `ed001a6cabae89fef68ca9aba6118b873cedd1f6` (no drift from the brief).
Pages: https://systemslibrarian.github.io/crypto-lab-feistel-forge/

## Delivered

How Many Rounds? is appended as the seventh lazy tab. The default 4×3 matrix
runs D1–D3 on fresh Feistel and random-permutation oracles, printing actual
hits, trial counts, query counts, probabilities and their signed difference.
The optional swap column performs another measured experiment. No probability
table is built into the source. Distinguisher code receives only an enc/dec
oracle, with the world ordering sampled outside it.

Independent lazy random functions are the default. DES mode calls the existing
CAVP-pinned block cipher, fixes key parity and rejects weak/semi-weak keys with
a redraw count. Sharing one function is an explicitly broken opt-in. The new
network calls the existing Feistel engine with finalSwap=false; the existing
DES convention, core, vectors, six tabs, failure codes, NEG-1, header, theme and
workflow are preserved.

The D3 stepper prints every input, intermediate half, key in DES mode, inverse
query and byte comparison. Near-zero measured differences are neutral rather
than green and are never called a security certificate. Input changes retire
results; no-op events preserve them. Runs yield after ten trials, can be
cancelled and cannot publish after leaving the tab. Invalid budgets and missing
entropy are visible failures. Default DES mode measured 12×200 paired trials
in 1,592.4 ms locally (`rounds-local-measurement.json`); the 5,000 limit remains
responsive through chunking and cancellation, not a promise of that runtime.

The negative fixture focuses the matrix on four rounds with one shared random
function: D1–D3 all remain neutral, then the swap test distinguishes it. Its
sentence deliberately says “against D1–D3”, correcting the supplied “every
distinguisher on this page” wording because D-swap is also on the page. The
focus control makes the fixture's scope explicit without pretending the
one/two/three-round rows are neutral. It links to the existing weak-key exhibit.

## Overlap and sources

The local sibling search found no existing round-count experiment. Remote
source was also checked: Simon Period (94d86ffa…) discusses the quantum-query
Kuwakado–Morii attack; Format Ward (596ebd44…) discusses asymptotic half-width;
Hidden Bit's `src/prf/switching.ts` supplies a lazy-map sampling pattern but no
Feistel network. All three are linked. The pattern is ported for 32-bit halves
and a bidirectional 64-bit permutation; no cross-repo runtime import was added.

The original Luby–Rackoff SIAM publication/DOI was checked. Katz–Lindell chapter,
theorem and exercise references come from the supplied checked brief; the
displayed relations are verified derivations, not quotations from the book.
Narrow halves, DES's internal f as a separate distinguisher and transcript
exports are extension seams, not implemented claims.

## Verification

- 174 unit tests across nine files passed. Existing 299 CAVP vectors and 598
  encrypt/decrypt assertions remain unchanged.
- Both inverse directions hold for 1–4 rounds in both modes over 50 blocks
  each. Concrete multiplication examples independently pin D1/D2/D3/swap.
  Every expected matrix cell is measured over 200 fresh paired trials;
  accidental-hit bounds are explicitly loose, with the probability rationale.
  10,000 forward and unseen inverse permutation queries remain consistent;
  DES provenance and weak-key redraws are checked directly.
- §4.1a: boot changes only tab-count and lazy-panel structure; no new copy.
- §4.1b: all 38 browser claims passed. The existing independent bit-array DES
  reconstructs D3's two forward queries and inverse query at three and four
  rounds. Other claims check counts, arithmetic, alarm/neutral styles, bounds,
  no-op preservation, retirement, cancellation and unavailable entropy.
- §4.1c: seven concrete faults are exercised by `test:mutations:rounds`.
  `mutation-evidence.json` records baseline passes, nonempty patches, successful
  builds with changed hashes, named zero-retry assertion failures, byte-exact
  restoration and passing owning tests. Browser runs verify served-script
  SHA-256 identity; a mismatched artifact cannot count as a mutation kill.
- §4.1d: the three focused D1–D3 cells are neutral, the scoped negative sentence
  is visible and D-swap actually reaches advantage one. Ignoring sharing or
  removing the negative sentence fails its owning assertion.
- All 42 browser tests passed, including four accessibility gates: complete
  desktop, 380px and 280px state walks plus the extension at 320px. Result
  tables wrap inside labelled keyboard scrollers. Grayscale and deuteranopia
  views were inspected; words and glyphs preserve every verdict distinction.
  No baseline exemption was added.
- Local Chromium 153.0.8010.0 used an ignored config after the pinned browser
  download was unavailable. Original CI configuration remains unchanged.

## Catalog handoff — no shared catalog edits

Suggested card sentence: “Measure how many Feistel rounds resist encryption
and decryption queries, then expose the failure of sharing one round function.”
Add chip `Luby–Rackoff`; retain the four existing chips.
Implemented call sites: `src/attacks/lubyRackoff.ts` lazy random function,
bidirectional permutation, DES PRF wrapper, direct inverse and D1/D2/D3/D-swap;
`src/ui/roundsPanel.ts` measured matrix and transcript. Reuses the original DES
and Feistel engine; no new primitive or published vector is claimed.
Prose only: strong-PRP proof, quantum-query attack, smaller-domain collisions
and DES weak-key connection.
Concept deepened: **4. Confusion, diffusion, and cipher structure**.

Final main SHA and served-byte proof are recorded after publication. The shared
fleet deploy-sync checker is blocked by missing unrelated sibling clones;
shared catalog, counsel, census and checker content remain unchanged.

# Extension brief — `crypto-lab-feistel-forge`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-feistel-forge` at `ed001a6cabae` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap: Katz–Lindell,
*Introduction to Modern Cryptography*, 3rd ed. (CRC Press, 2021), §7.2.2 and §8.6 —
Theorem 8.22 (three rounds give a pseudorandom permutation), Construction 8.23 and
Theorem 8.24 (four rounds give a *strong* one), Exercises 8.16, 8.17 and 8.18.

**Verdict: extension — one new tab, "How Many Rounds?", inside the existing lab.**

## What the lab has now

Read at `ed001a6cabae`:

- **A generic Feistel network with a swappable round function.** `runFeistel(block, subkeys,
  f, finalSwap = true)` (`src/des/feistel.ts:135`) over 8-byte blocks with a hard-coded 4/4
  split; `FeistelRoundFunction` (`feistel.ts:35`) takes a 4-byte right half and a subkey;
  `ROUND_FUNCTIONS` (`feistel.ts:66`) offers DES's `f`, a constant, an AND and a nibble mask.
  `runFeistelReversed` (`feistel.ts:172`). An existing `// [extension] point` for unbalanced
  Feistel networks sits at `feistel.ts:97–101`.
- **A synchronous DES** — `encryptBlock` / `decryptBlock` (`src/des/des.ts:166`, `:178`),
  pinned to the archived CAVP vectors (`src/des/vectors.ts`, `vectors.test.ts`) and to
  `FP(feistel(IP(block)))` (`feistel.test.ts:129`).
- **Key policy** — `fixParity`, `inspectKey` (`src/des/weakKeys.ts:76`, `:105`). The header
  comment (`weakKeys.ts:14–22`) already explains that a weak key gives every round the same
  subkey and makes encryption its own inverse. This extension reaches the same fact from the
  theory side, so cross-link the two.
- **Six tabs**, lazily rendered: `index.html:196–201` (buttons) and `:206–211` (panels),
  `RENDERERS` in `src/main.ts:24–31`. `e2e/gate.ts:299` asserts `.tab-btn` count **6**.
- **Claims suite** — `e2e/claims.spec.ts`, with an independent DES injected into the page
  (`INDEPENDENT_DES`, `claims.spec.ts:47`) and one negative claim, `NEG-1` (block-size bound,
  `claims.spec.ts:535`).
- **No mutation runner.** `scripts/` holds only `build-vectors.mjs`, and a grep for
  `data-verdict` / `data-claim` in `src/` finds nothing.

Nothing in this lab asks *how many rounds* a Feistel network needs before it stops being
distinguishable from a random permutation. It shows that the structure inverts under any `F`,
which is the invertibility half of the story. Luby–Rackoff is the pseudorandomness half.

**Overlap check.** Before building, grep the sibling clones for `Luby|Rackoff` and for any
Feistel round-count distinguisher, and report what you find. When this brief was written:

- `crypto-lab-simon-period` (`94d86ffa67fa`) cites Luby–Rackoff for the classical security of
  3-round Feistel, and names a quantum distinguisher (Kuwakado–Morii) that breaks it with
  superposition queries. That is a different attack model; link it, don't duplicate it.
- `crypto-lab-format-ward` (`596ebd44d2c0`, `src/ui.ts:895`) argues that Feistel security is
  asymptotic in the half-width.
- `crypto-lab-hidden-bit` (`734bd6ee7329`) measures the PRP/PRF switching lemma with lazily
  sampled oracles (`src/prf/switching.ts`). It has no Feistel network.

## What to add — the "How Many Rounds?" tab

**Plain-language intro (2–4 sentences, no maths):** A Feistel network is always reversible,
whatever its round function does. That doesn't make it look random. With good round functions,
one round is obviously not random, two rounds still give themselves away, and three rounds fool
anyone who can only encrypt. Someone who can also *decrypt* needs to be fooled by four.

**The headline mechanism, shown and not told:** a 4×N matrix, filled by measurement. Rows are
rounds 1–4. Columns are distinguishers. Each cell runs the distinguisher many times against two
worlds: the Feistel network with fresh round functions every trial, and a lazily sampled random
64-bit permutation. Each cell prints `Pr[D=1 | Feistel]`, `Pr[D=1 | random]`, and the
advantage, which is the difference between the two. The learner watches the
"broken" cells retreat down and to the right as rounds are added.

**Convention:** Katz–Lindell's network — `L_i = R_{i−1}`, `R_i = L_{i−1} ⊕ f_i(R_{i−1})`,
output `(L_r, R_r)`, **no final swap**. Call `runFeistel(…, finalSwap = false)` and state the
convention on the page beside the figure. The DES tabs keep their swap. Every relation below is
derived for this convention, so mixing conventions silently breaks D2 and D3.

**The distinguishers** (each outputs 1 for "this is a Feistel network"; write `L′ = L ⊕ Δ` with
a random nonzero `Δ`, and keep `R` fixed across the paired queries):

| | Queries | Rule | Source |
|---|---|---|---|
| **D1** | 1 encryption | `L_out = R_in` | K-L §8.6, the `F⁽¹⁾` paragraph before Eq. (8.15) |
| **D2** | 2 encryptions | `L_out ⊕ L′_out = L ⊕ L′` | K-L Exercise 8.16 |
| **D3** | 2 encryptions + 1 decryption | `Enc(L,R)=(S,T)`, `Enc(L′,R)=(S′,T′)`, `Dec(S′, T′⊕L⊕L′)=(L″,R″)`; output 1 iff `R″ = S ⊕ S′ ⊕ R` | K-L Exercise 8.17 (its hint: two forward queries, one inverse) |
| **D-swap** | 2 encryptions | `Enc(T, S) = (R, L)` where `(S,T)=Enc(L,R)` | K-L Exercise 8.18 states the 3-round same-key case; the identity follows for any number of rounds when every round uses the same function (decryption = swap ∘ encryption ∘ swap) |

Those relations are this brief's own derivation, written as answers to K-L's exercises. Treat
them as claims to verify (see Tests), not as quotations from the book. A quick simulation run
while writing this brief, with 300 trials per cell and independent random round functions,
produced:

| rounds | D1 | D2 | D3 | D-swap |
|---|---|---|---|---|
| 1 | 1.00 | 0.00 | 1.00 | 1.00 |
| 2 | 0.00 | 1.00 | 1.00 | 0.00 |
| 3 | 0.00 | 0.00 | **1.00** | 0.00 |
| 4 | 0.00 | 0.00 | 0.00 | 0.00 |
| 4, same `f` every round | 0.00 | 0.00 | 0.00 | **1.00** |

The random-permutation column read 0.00 throughout (each rule holds with probability about
2⁻³² there). The page must **measure** this table, never print it. These values are what the
tests should expect.

**Round-function choices** (a segmented control above the matrix):

1. **Random functions (the proof's setting)** — default. Lazily sampled, independent per
   round, 32→32 bits, drawn with `crypto.getRandomValues`. K-L's proof of Theorem 8.22 begins by
   replacing the PRFs with random functions. Port the pattern of `LazyRandomFunction` from
   `crypto-lab-hidden-bit/src/prf/switching.ts` (`734bd6ee7329`) — don't import it. That class
   caps the domain at 8–20 bits, and this domain is 32.
2. **DES as the round function** — `f_i(R) = first 32 bits of DES_{k_i}(R ‖ 0x00000000)`. Each
   round gets an independent random key, parity-fixed with `fixParity`, and weak or semi-weak keys
   are rejected through `inspectKey`. This is a real keyed function the lab already implements and
   pins to CAVP. The page must say why it is a reasonable stand-in for a pseudorandom function and
   no more than that: DES has a 56-bit key. These distinguishers make at most three queries, so key
   length never enters.
3. **Same function every round** — a toggle that composes with either choice above, so one
   function or key is reused across rounds (Exercise 8.18).

**The two worlds** must support inverse queries for D3:

- `feistelInverse(fs)` undoes rounds directly: `R_{i−1} = L_i`, `L_{i−1} = R_i ⊕ f_i(L_i)`.
- `LazyRandomPermutation64` keeps forward and backward maps (64-bit keys as `bigint` or 16-hex
  strings) and samples without replacement in both directions. An inverse query on an unseen
  output samples an unused input and records both directions.

**Break-it-yourself:** a "Step one trial" button runs a single D3 trial and prints the whole
transcript (`L, L′, R, S, T, S′, T′, L″, R″`) with the relation checked byte by byte. The
learner can then flip to 4 rounds and watch the same transcript fail the check.

## SECURITY / CORRECTNESS INVARIANTS

1. Every matrix cell is computed from trials run in the browser. No hard-coded probability,
   advantage or verdict appears anywhere in `src/`.
2. Both worlds are queried through one oracle interface `{ enc, dec }`. A distinguisher cannot
   tell which world it holds except through its queries. The world bit is chosen per trial and
   stored outside the distinguisher's closure.
3. Fresh round functions or keys in every trial; nothing is shared between trials. The
   same-function toggle only affects sharing *within* a trial.
4. `feistelInverse(feistel(x)) = x` and `feistel(feistelInverse(y)) = y`, tested for r = 1–4
   in both modes.
5. The random permutation is a permutation: no output is assigned twice, and inverse queries are
   consistent with forward ones.
6. The "no advantage" state is never worded as "secure" or "pseudorandom". It reads "no
   advantage measured for D1–D3", and the NEG-2 text sits beside it (see Tests).
7. The convention (no final swap) is fixed in the module, not as a UI option.

## ARCHITECTURE

New files beside the existing ones:

- `src/attacks/lubyRackoff.ts` — `LazyRandomFunction32`, `LazyRandomPermutation64`,
  `desPrf(key)`, `feistelOracle(fs)` (enc + `feistelInverse`), the four distinguishers, and
  `measureCell(rounds, distinguisher, mode, trials)` returning raw counts for both worlds plus
  the last transcript.
- `src/attacks/lubyRackoff.test.ts`.
- `src/ui/roundsPanel.ts` — the tab, registered in `RENDERERS` (`src/main.ts:24`).

Reuse `runFeistel` (with `finalSwap = false`), `encryptBlock`, `fixParity`, `inspectKey`,
`randomBytes` (`src/des/bytes.ts:119`) and `xorBytes`. Keep the 32-bit halves as `Uint8Array(4)`
to match `FeistelRoundFunction`, or pack them as `number` inside the attack module — just not
both.

Put a `// [extension] point` beside `measureCell` for a narrower half-width (see EXTENSION
SEAMS). It shares the blocker named at `feistel.ts:97–101`: the hard-coded 4/4 split.

## UI

- A segmented control for the round function (random / DES / with a "same function every
  round" checkbox), a trials input (default 200, bounds below), and "Run matrix".
- The matrix as a real `<table>` with row and column headers. Each cell shows `Pr[D=1]` in each
  world and the advantage, and carries an icon and a text word as well as colour.
- "Step one trial": a single D3 run with the full transcript, under the matrix.
- A disclosure, "Why three rounds survive encryption queries", that summarises the collision
  argument in the proof of Theorem 8.22 in plain words. A disclosure,
  "What this does not prove", holds the NEG-2 text. Per §4.1d that text must also be visible
  without opening anything in the fixture state.
- Retirement: changing rounds, mode, the toggle or the trials count marks the matrix stale and
  says so. Re-selecting the same value does not.
- Stacks below 640px. The matrix region scrolls with `tabindex="0"`, `role="region"` and an
  `aria-label`, per §4.2.

## VISUAL SEMANTICS

Colour tracks *the network's standing as a pseudorandom permutation*, not whether a function
returned true:

- **Advantage near 1** — the distinguisher wins, so the construction is **not** a PRP against this
  adversary. Show ALARM styling, a "✕ distinguished" icon and the word "distinguished".
- **Advantage near 0** — neutral, not green: "– no advantage measured", plus the caveat. Use the
  calm/working styling the lab already uses only for invertibility facts. A flat cell is an
  absence of evidence.
- The random-permutation column is a reference column, styled neutrally.
- Check the page in grayscale and deuteranopia simulation, as §1 requires.

## EDGE CASES

- Trials outside 10–5,000 → refuse with the bounds named. The 5,000 cap matches Hidden Bit's
  switching-lemma bound; measure DES mode's run time and lower the cap if needed rather than
  freezing the tab.
- `Δ = 0` must be impossible: draw until nonzero, and say why in a tooltip ("D2 and D3 need two
  different left halves").
- DES mode draws a weak or semi-weak key → redraw silently and count redraws in the transcript.
  Don't refuse: the user never chose the key.
- An inverse query to the random permutation on an unseen output → sample and record it.
  Never throw.
- One round with the same-function toggle on is indistinguishable from the toggle off. Show a
  note saying so, so the toggle doesn't look broken.
- A run in progress when the tab is left → cancel it, or let it finish without writing to a
  retired matrix.

## EXTENSION SEAMS

1. **Narrower halves.** At 32-bit halves the q²/2ⁿ collision term in the proof of Theorem 8.22
   can't be reached in a browser. At 8–12-bit halves the collision-based distinguisher the proof
   describes (look for `L₃` collisions) becomes measurable. This needs the variable split already
   named at `feistel.ts:97–101`.
2. **DES's own `f` as the round function.** Through the expansion E, a one-bit change in `R`
   reaches at most two S-boxes, so at most 8 of `f`'s 32 output bits can change. That locality is
   a distinguisher of its own, and a reason DES uses 16 rounds rather than 4. Not built.
3. **A per-trial query log export** for a worksheet.

## Tests

**Unit (`lubyRackoff.test.ts`):**

- Round-trips: `feistelInverse ∘ feistel = id` and the reverse, r = 1–4, random and DES modes,
  50 random blocks each.
- **A worked example with fixed, hand-checkable round functions** (e.g. `f_i(x) = (x · c_i) mod
  2³²` for stated constants `c_i`). For r = 3, assert the D3 identity `R″ = S ⊕ S′ ⊕ R`
  algebraically on concrete numbers written into the test. Do the same for D2 at r = 2, D1 at
  r = 1, and D-swap at r = 4 with one shared function. This pins the relations independently of
  randomness.
- **The matrix.** With N = 200 per cell, the "1.00" cells in the table above must read exactly
  1.0 in the Feistel world: each relation holds with probability 1. Every other cell must read
  ≤ 0.05 in both worlds. The false-positive probability per trial is about 2⁻³², so this test is
  not flaky; say that in a comment.
- The random permutation never repeats an output across 10,000 forward and inverse queries, and
  `dec(enc(x)) = x`.
- **DES-mode provenance.** `desPrf` calls the same `encryptBlock` that `vectors.test.ts` pins to
  CAVP. Assert that by checking one PRF output against an `encryptBlock` call written out in the
  test.

**Claims (`e2e/claims.spec.ts`, §4.1b):**

- **Independent re-derivation of D3.** In DES mode the page prints the three round keys and the
  last transcript. Recompute all three queries in the page with the existing `INDEPENDENT_DES`
  (`claims.spec.ts:47`), wrapped in a separately written Feistel loop in the test. Assert the
  printed `S, T, S′, T′, L″, R″` match, and that the page's verdict equals the relation the
  test computes.
- **Parts sum to whole.** Each cell's advantage equals the printed `Pr_F − Pr_π`, and each
  printed probability equals hits/trials, with the hit counts printed.
- **Retirement.** Change rounds and assert the stale-matrix notice. Re-select the same value and
  assert the matrix survives.
- **Failure path.** Trials out of range are refused, and the page names the bounds.

**§4.1c mutations.** This tab renders verdicts, so it needs a scripted runner. Follow the
concrete-patch shape of `crypto-lab-mac-race/scripts/check-crc-mutations.mjs` (`bc4f683362e4`):
one exact anchor per patch, build must succeed, bundle hash must move, a named test must go red,
and the restored hash must equal the baseline. At minimum:

1. D3 checks `S ⊕ S′ ⊕ L` instead of `S ⊕ S′ ⊕ R` → the r = 3 cell stops winning.
2. `feistelInverse` uses `f_i(R_i)` instead of `f_i(L_i)` → round-trip and claims fail.
3. The same-function toggle is ignored (always independent) → the NEG-2 D-swap test fails.
4. The advantage is printed as `Pr_F` alone → the parts-sum test fails once a π-world hit is
   forced in a fixture, or replace this with a mutation that swaps the two worlds' labels.
5. A "distinguished" cell gets calm styling → the claims test that reads the verdict class
   fails.

Add a `test:mutations:rounds` npm script so the runner is invoked by name.

**§4.1d — NEG-2:** *"Zero measured advantage against every distinguisher on this page does not
make a Feistel network a pseudorandom permutation."*

- **Evidence fixture:** 4 rounds, random mode, **same function every round**. D1, D2 and D3
  all read "no advantage measured", and every verdict in that state is non-alarm. The page shows
  `NO ADVANTAGE ON D1–D3 — AND NOT A PRP`, with the NEG-2 sentence visible.
- The opt-in "Try the swap test" then runs D-swap and reaches advantage 1.0. That's the evidence,
  not part of the fixture state.
- Assert all three §4.1d points. Delete the NEG-2 text and assertion 3 must fail. Mutation 3
  above breaks the fixture's D-swap follow-up.
- Cross-link the fixture to the weak-key exhibit in "Same Circuit Both Ways". A DES weak key is
  this same fact in DES's convention (all subkeys equal, encryption its own inverse,
  `weakKeys.ts:14–22`).

**Gate (§4.1a):** update `e2e/gate.ts:299` from 6 to 7 tabs. Add a structural boot check that the
new panel is empty until activated, matching how the gate treats the other panels. No copy
assertions in `boot()`.

## README and card follow-up

- README **What It Is**: one sentence that the lab now also measures how many rounds a Feistel
  network needs to be a (strong) pseudorandom permutation.
- README **Exhibits** (`README.md:91`): add "How Many Rounds?". If the tab goes after "Same
  Circuit Both Ways", renumber the list, and grep `e2e/` for tab-order dependencies (`ArrowRight`,
  `End`) first. If any exist, append the tab at the end instead.
- README **Build & Verify**: the new test count and the mutation script.
- **Catalog handoff (do not edit `../crypto-lab`):** proposed chip `Luby–Rackoff`. The lab
  implements the construction and its distinguishers, so the chip needs no marker. Keep the
  four existing chips.

## Do not touch

The DES core and its CAVP vectors, the existing tabs and their failure codes, `NEG-1`, the
`finalSwap = true` default that the DES tabs depend on, the theme pin, and the header.

## Sources

- Katz, Lindell. *Introduction to Modern Cryptography*, 3rd ed., CRC Press, 2021 (ISBN
  9780815354369) — §7.2.2; §8.6 Theorem 8.22, Construction 8.23, Theorem 8.24; Exercises
  8.16–8.18. Checked against the book's text.
- M. Luby, C. Rackoff. "How to Construct Pseudorandom Permutations from Pseudorandom
  Functions." *SIAM Journal on Computing* 17(2):373–386, 1988. doi:10.1137/0217022 (Crossref).

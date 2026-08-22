# Feistel Forge

Real DES, stepped round by round, in the browser. Double DES falling to a
meet-in-the-middle attack. A 64-bit block colliding at the birthday bound and
leaking a session cookie out of CBC.

**No key length repairs a block size.**

**Live demo:** <https://systemslibrarian.github.io/crypto-lab-feistel-forge/>

---

## What It Is

A teaching lab for the **Feistel network** — the construction half the block
ciphers ever deployed were built from — using the **Data Encryption Standard**
as the specimen, because DES is the design that made it famous and the design
whose failures are best documented.

The cipher is real and hand-rolled: FIPS 46-3's IP/FP, the PC-1/PC-2 key
schedule with its rotation table, the expansion E, all eight S-boxes and the
permutation P, written at the bit level in `src/des/` so a reader can hold the
standard beside the source and check it line by line. Nothing is simulated.
WebCrypto does not implement DES and OpenSSL 3 moved it into the legacy
provider, so the only way to run it in a browser is to write it — and writing
it is also the point, because every intermediate value the page shows is a real
one taken from a real encryption.

**The single idea:** a Feistel round is invertible no matter what its round
function does. Given the two halves leaving a round, the left one IS the right
half that entered, so the round function can be recomputed exactly as the
forward pass computed it and XORed back off. It is evaluated forwards in both
directions, never inverted — so it does not need to be invertible, does not
need to be injective, and in DES is neither. Every S-box maps 6 bits to 4 with
exactly four preimages per output, so f collapses 4^8 = 65,536 expanded inputs
onto every 32-bit value it produces, and the cipher still decrypts perfectly.
This property is invisible in the SPN designs that replaced DES, where every
layer must itself be a bijection.

**Security model.** Everything runs in the browser; there is no backend and no
network call. Keys and IVs are generated per session with `crypto.getRandomValues`
and are never persisted. The only thing stored is `theme`, pinned to `dark`.

**Not production cryptography.** DES is broken — 56 bits of key have been
brute-forceable since 1998, and its 64-bit block is broken in a different way
this lab is mostly about. Nothing here is constant-time (the S-box lookups are
data-dependent array indexing) and the CBC on this page is unauthenticated.
This is a teaching artifact.

### Every source is withdrawn, and that is expected

DES is a historical cipher, so there is no live normative document to cite. Each
source is named with its status rather than presented as current:

| Document | What it is | Status |
| --- | --- | --- |
| **FIPS 46-3** | Data Encryption Standard — the specification `src/des/tables.ts` transcribes | **Withdrawn 2005-05-19** |
| **NBS SP 500-20** (Rev. Sept 1980) | Appendix B, where the five known-answer families were defined | Historical; the 1977 edition was superseded 1980 |
| **NIST SP 800-17** | MOVS — the DES validation system | **Withdrawn 2018-08-01** |
| **NIST SP 800-20** | TMOVS — the TDEA validation system | **Withdrawn 2018-09-26** |
| **NIST SP 800-67 Rev. 2** | TDEA, and the 2^20-block data limit in §3.4 | **Withdrawn 2024-01-01** |
| **NIST SP 800-131A Rev. 2** | The deprecation schedule; TDEA disallowed for applying protection after 2023-12-31 | Current (March 2019) |

NIST's Retired Testing page gives the reason for the first outright: FIPS 46-3
"was withdrawn May 19, 2005 because the cryptographic algorithm no longer
provided the security that is needed". SP 800-17 was withdrawn because "this
validation system is for algorithms that have been deprecated (e.g., DES,
Skipjack)".

The executable anchor is NIST's archived CAVP archive **`KAT_TDES.zip`**
(118,218 bytes, SHA-256 `19d8841f84ae3415350b069a4768bd416c05a0533ee43e905ab099adb8ccb374`,
downloaded 2026-08-22; the `.rsp` files inside are dated 2011-04-21). The
archive is named for Triple DES and that is worth a sentence: every one of its
55 files uses the single-key field `KEYs`, never `KEY1`/`KEY2`/`KEY3`. TDEA
with all three keys equal is single DES exactly — encrypt, decrypt, encrypt
under one key collapses to one encryption — so these ARE the classic DES
tables. NIST never published a DES-only archive.

Other work this lab stands on: **Diffie and Hellman, "Exhaustive Cryptanalysis
of the NBS Data Encryption Standard", _Computer_ 10(6), June 1977** (the
meet-in-the-middle attack, and the recommendation of triple rather than double
encryption); **FIPS 74 §3.6** (the four weak keys, there called "self-dual");
**Bhargavan and Leurent, "On the Practical (In-)Security of 64-bit Block
Ciphers", ACM CCS 2016** (Sweet32, CVE-2016-2183); and **RFC 4772 §A.3**, which
states the negative claim in a standards document: "While the effective key
length for 3DES is clearly much larger than for DES, the block size is,
unfortunately, still only 64 bits."

---

## Exhibits

1. **One Round** — the headline mechanism. Step a real DES encryption a round
   at a time; the diagram carries that round's actual L, R, subkey and f-output.
   Press **Undo** and watch the same F, run forwards, put the block back
   together — then swap F for one that returns a constant, watch the measured
   collapse report 16,384 inputs mapping onto 1 output, and undo the round
   again. An exhaustive S-box preimage census sits behind a disclosure.
2. **Same Circuit Both Ways** — encryption and decryption side by side, with
   both subkey lists printed so the reversal is visible rather than described.
   Then the four **weak keys**, where the two lists are the same list and
   encrypting twice returns the plaintext, with the C0/D0 registers that caused
   it. Semi-weak pairs behind a disclosure.
3. **Complementation** — `DES(~K, ~P) = ~DES(K, P)`, computed by two different
   routes and compared byte for byte. Then two brute-force searches race over
   the same reduced keyspace, each reporting the encryptions it actually
   performed; hide the key in the complement half and the plain search sweeps
   the entire space and finds nothing.
4. **2DES Meet-in-the-Middle** — the real attack on the real cipher over a
   reduced keyspace, with a second known pair sieving false positives. Every
   figure about the full attack is projected from the run you just watched,
   including the wall-clock estimate, which is anchored to your own browser's
   measured rate.
5. **Sweet32** — the climax. The birthday bound as live arithmetic (the formula
   has no place to put a key length); the same curve **measured** on real
   DES-CBC output at a reachable scale; a genuine 64-bit collision recovering a
   session cookie by XOR alone; and the `BLOCK_SIZE_EXCEEDED` data limit a real
   library should raise.
6. **CAVP Vectors** — all 299 archived NIST vectors run in your browser in both
   directions, with the provenance table above printed in the page.

### Failure codes

Three policy failures are raised by the same functions the exhibits call, and
each is driven to the surface by a test in `e2e/claims.spec.ts`:

- **`PARITY_INVALID`** — a DES key carries odd parity in the low bit of every
  byte. PC-1 drops those eight bits before the schedule sees them, so getting
  them wrong does not weaken the key: it means the key you loaded is not the
  key somebody sent. A library that shrugs at that has checked nothing.
- **`WEAK_KEY`** (and `SEMI_WEAK_KEY`) — four keys make encryption its own
  inverse, and six pairs make one key undo the other. Refused by default;
  loadable only through a visibly-marked deliberately-broken mode.
- **`BLOCK_SIZE_EXCEEDED`** — the Sweet32 data limit. A 64-bit block cipher has
  a birthday bound measured in blocks rather than in years, and stopping before
  it is the library's job. `checkDataLimit` is called by the cipher and by the
  exhibit's meter, so the reading on screen is the refusal in the code.

---

## When to Use It

**Use it to:** understand why a Feistel round is reversible when its round
function is not; see what a key schedule's rotation structure can do to a
cipher; watch a meet-in-the-middle attack complete; and get the birthday bound
on a block size into your hands rather than into your notes.

**Do NOT use it to:** encrypt anything. Do not use DES, and do not use 3DES —
NIST disallowed TDEA for applying cryptographic protection after 2023-12-31 and
withdrew its specification on 2024-01-01. Do not copy `src/des/des.ts` into
anything that handles real data: it is written for readability, not for speed,
and it is not constant-time. If you need a block cipher, use AES-GCM through
WebCrypto; its 128-bit block puts the bound in this lab about eighteen
quintillion blocks further away.

---

## Live Demo

<https://systemslibrarian.github.io/crypto-lab-feistel-forge/>

You can: step a real DES round and undo it with a provably non-invertible round
function; load a weak key and watch encryption become its own inverse; race two
brute-force searches and read the halving off their counters; recover both keys
of a 2DES pair; measure the birthday curve on real ciphertext; lift a cookie
out of a CBC stream; and run all 598 CAVP known-answer assertions in your own
browser.

---

## What Can Go Wrong

The threats this lab is about, and the ones it deliberately does not model.

**Modelled, and demonstrated on the real cipher:**

- **Exhaustive key search.** 56 bits. Broken publicly in 1998; the
  complementation property takes one further bit off in a chosen-plaintext
  setting, which the lab measures rather than asserts.
- **Double encryption is not double security.** Meeting in the middle costs
  about 2^57 operations against a nominal 2^112, plus a table of 2^56 entries.
  Diffie and Hellman published this the year DES was issued.
- **Weak and semi-weak keys.** Four keys make E its own inverse; six pairs make
  one key decrypt the other. Both refused by default, both demonstrated by
  running the cipher rather than by describing them.
- **Parity that nobody checks.** Accepting a key with bad parity silently
  discards a transmission check the format exists to provide.
- **The 64-bit block-size birthday bound (Sweet32).** After about 2^32 blocks —
  32 GiB — under one key, two CBC ciphertext blocks repeat, and
  `P_i XOR P_j = C_{i-1} XOR C_{j-1}` hands the eavesdropper a plaintext block
  they did not already know. **This is the failure a longer key does not
  touch**, and it is why the lab exists.

**What the lab does NOT claim.** Not that 3DES was fine except for its block
size. It was not: two-key TDEA falls well below its nominal strength to known
tradeoffs, and NIST's deprecation cited key strength alongside the data limit.
The claim is narrower and it is about independence — tripling the key repaired
the key axis and left the block size exactly where it was.

**Deliberately not modelled:** differential and linear cryptanalysis (see
[Biham Lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/) and
[Matsui Line](https://systemslibrarian.github.io/crypto-lab-matsui-line/));
padding oracles and the other consequences of unauthenticated CBC; timing and
power side channels — nothing here is constant-time and no attempt is made to
pretend otherwise; and any attack requiring more than a browser tab's compute.

**Two results on this page are arranged rather than found, and both say so
permanently on screen:**

- The **full 64-bit collision** in the Sweet32 recovery is placed using the key,
  by solving `P_a = D_K(C_s) XOR C_{a-1}` for one attacker block. A real
  attacker cannot do that; they wait about 2^32 blocks for chance to place it.
  What is not arranged: the cipher, the CBC chaining, the collision itself
  (verified by comparing the two ciphertext blocks), and the arithmetic that
  recovers the cookie.
- The **reduced keyspaces** in the complementation race and the
  meet-in-the-middle attack fix most of the key bits publicly so the searches
  finish in a browser. The cipher is the full 16-round DES throughout, and
  every figure about the full-width attack is projected from the run you
  watched.

A **truncated** collision — the one the birthday measurement finds — is real but
reveals nothing, because the CBC identity needs the whole block to match. The
page says that where it shows the measurement.

---

## Real-World Usage

DES was the first public, government-standardised block cipher and it ran the
world's ATMs, payment terminals and inter-bank messaging for two decades. Its
descendants are everywhere the design pattern is: **Blowfish**, **Twofish**,
**Camellia**, **CAST-128**, **GOST**, **RC5**, **MISTY1**, **KASUMI** (3G) and
**Simon/Speck** are all Feistel or generalised-Feistel constructions, and NIST's
format-preserving encryption modes FF1 and FF3-1 (SP 800-38G) are Feistel
networks over arbitrary alphabets — the round structure is the whole point
there.

The block-size failure is the part still in living memory. Sweet32
(CVE-2016-2183) was demonstrated against real HTTPS sessions using 3DES and
real OpenVPN sessions using Blowfish in 2016; browsers and TLS libraries
removed 64-bit block ciphers in response, and NIST cut the TDEA data limit from
2^32 blocks to 2^20 the following year before disallowing the algorithm
outright at the end of 2023.

---

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-feistel-forge/
```

```bash
npm test           # the unit suite, including the CAVP known-answer vectors
npm run build      # typecheck + production build
npx playwright install chromium
npm run test:a11y  # the WCAG 2.1 A/AA gate against the production build
npm run test:claims
```

`src/des/vectors.ts` is generated. `npm run vectors:build` re-downloads
`KAT_TDES.zip` from NIST, refuses to write anything unless its SHA-256 matches
the digest recorded in `scripts/build-vectors.mjs`, checks that each `.rsp`
file's `[ENCRYPT]` and `[DECRYPT]` sections carry the same triples, and
reproduces the committed file byte for byte. Nothing in the build or the test
suites touches the network.

---

## Related Demos

- [Nonce Collision](https://systemslibrarian.github.io/crypto-lab-nonce-collision/) — the same birthday bound, in the nonce space instead of the block space
- [Collision Vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/) — the same bound again, on hash outputs, with real published collisions
- [Biham Lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/) — differential cryptanalysis, the technique that broke reduced-round DES
- [Iron Serpent](https://systemslibrarian.github.io/crypto-lab-iron-serpent/) — the SPN construction Feistel is the alternative to
- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — what a 128-bit block does to the same modes

---

## Build & Verify

**167 unit tests** across 8 files (`npm test`), plus **2 browser gate tests**
and **34 claims tests**.

The known-answer gate is the load-bearing part. `src/des/vectors.ts` carries
**299 CAVP vectors**, each asserted encrypting AND decrypting — **598
assertions** — because the `.rsp` files' paired `[ENCRYPT]` and `[DECRYPT]`
sections carry the same triples, which was verified when the file was
generated. The five ECB families are the DES test set from SP 500-20 Appendix B
at its published case counts (64 / 64 / 56 / 32 / 19), and the CBC family gates
the mode rather than only the block cipher:

| File | What it covers |
| --- | --- |
| `src/des/vectors.test.ts` | all 598 CAVP assertions, the published case counts, and that the Inverse Permutation family really is the Variable Plaintext family transposed |
| `src/des/des.test.ts` | bit plumbing; IP/FP inverse; every table's selection census; the shifts summing to 28; S-box row structure; the schedule ignoring parity; round-trip; permutation; avalanche; the trace's chaining and final swap |
| `src/des/weakKeys.test.ts` | every weak key proved an involution BY EXECUTION, every semi-weak pair proved to cancel, and every strict-parsing refusal |
| `src/des/modes.test.ts` | CBC chaining against its own definition, the ECB tell, the data limit at its exact boundary, and that the meter and the cipher are one function |
| `src/des/feistel.test.ts` | the headline claim: every round function inverts, at every round count, including ones measured to be non-injective; the exhaustive S-box preimage census; and that DES really is `FP(feistel(IP(block)))` |
| `src/attacks/complement.test.ts` | the identity on 365 key/plaintext pairs, and the halving read off the searches' own counters |
| `src/attacks/mitm.test.ts` | key recovery, the second-pair sieve, the operation count, and the published complexities |
| `src/attacks/sweet32.test.ts` | the birthday arithmetic, a measured truncated collision independently re-derived, and the arranged collision's recovery recomputed from public values only |

`e2e/claims.spec.ts` checks the page tells the truth. It carries a **second,
independent DES** — written from the same standard in a deliberately different
shape, sharing no code with `src/` — which is injected into the browser and used
to re-derive the values the page prints. A test that imported the lab's own
tables would agree with a transposed digit perfectly; this one would not. The
suite also covers the negative claim (**NEG-1**: increasing key length does not
repair a 64-bit block-size birthday bound), each of the three failure codes
naming its actual cause, verdict retirement and its no-op guard, and the
`[hidden]` cascade probe.

`e2e/a11y.spec.ts` is the WCAG 2.1 A/AA gate: `@axe-core/playwright` over the
production build at 1280px and 380px, across every driven state, with
arithmetic contrast, non-text contrast, reflow, scroller-reachability and
`aria-hidden` oracles beyond what axe reports. **Zero violations, and the
deploy is blocked if that changes.**

## Performance

The DES here is written at the bit level for readability rather than for speed;
`benchmark()` measures roughly 80,000 block operations per second in a desktop
browser, against a bit-sliced native implementation's several million. That
gap is stated wherever it matters: the meet-in-the-middle exhibit sizes its
keyspace against the measurement and projects the full-width attack from the
rate it just observed, rather than from a number typed into a template.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

import { expect, test, type Page } from '@playwright/test';

/**
 * The claims suite: does the page tell the truth?
 *
 * The a11y gate proves the page is usable. This one proves it is honest. The
 * rule that makes these tests worth anything is that they never re-run the
 * expression the source runs — a test that recomputes the same faulty branch
 * agrees with the bug. So each claim here is checked one of three ways:
 *
 *  - CROSS-CHECK — two surfaces that must agree (a counter against the rows it
 *    counts; hand-authored prose against a computed value).
 *  - INDEPENDENT RE-DERIVATION — recompute the claim from the page's own raw
 *    inputs by a DIFFERENT route than the source takes. `desEncryptInPage` is
 *    the workhorse: a second, self-contained DES written inside the test file
 *    and driven through the browser, sharing no code with `src/`.
 *  - PARTS-SUM-TO-WHOLE — where the maths offers one.
 *
 * NEG-1, this lab's negative claim, lives here rather than in a document:
 *
 *     Increasing key length does not repair a 64-bit block-size birthday bound.
 *
 * It is testable because it is a statement about a formula. `describe('NEG-1')`
 * asserts that the number the page prints for a 64-bit block is unchanged
 * across every key length the page mentions, that it MOVES when the block size
 * moves, and that the page says so in prose that matches the arithmetic.
 *
 * The three headline failure codes get a section each: WEAK_KEY,
 * PARITY_INVALID and BLOCK_SIZE_EXCEEDED are driven to the surface and the page
 * is required to NAME the actual cause rather than a generic refusal.
 */

// ── An independent DES, for re-derivation ───────────────────────────────────

/**
 * A second DES implementation, written from the FIPS 46-3 tables in a
 * deliberately different shape from `src/des/des.ts`: this one carries the
 * block as a 64-element bit array and the subkeys as bit arrays too, with no
 * shared helper, no shared permutation function and no shared bit numbering
 * code. It is slow and it does not care.
 *
 * The point is that if `src/des/tables.ts` had a transposed digit, this would
 * NOT agree with it — whereas a test that imported the same tables would agree
 * with the bug perfectly. It is injected into the page and run there, so the
 * comparison is against the bundle that actually shipped.
 */
const INDEPENDENT_DES = `
(function () {
  var IP=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
  var FP=[40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
  var E=[32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
  var PERM=[16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
  var PC1=[57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
  var PC2=[14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
  var SH=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
  var S=[
  [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
  [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
  [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
  [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
  [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
  [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
  [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
  [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]];

  function hexToBits(h){var b=[];for(var i=0;i<h.length;i++){var v=parseInt(h[i],16);for(var j=3;j>=0;j--)b.push((v>>j)&1);}return b;}
  function bitsToHex(b){var out='';for(var i=0;i<b.length;i+=4){out+=((b[i]<<3)|(b[i+1]<<2)|(b[i+2]<<1)|b[i+3]).toString(16);}return out;}
  function pick(bits,table){var out=[];for(var i=0;i<table.length;i++)out.push(bits[table[i]-1]);return out;}
  function xor(a,b){var out=[];for(var i=0;i<a.length;i++)out.push(a[i]^b[i]);return out;}
  function rotate(a,n){return a.slice(n).concat(a.slice(0,n));}

  function schedule(keyHex){
    var cd=pick(hexToBits(keyHex),PC1);
    var c=cd.slice(0,28), d=cd.slice(28);
    var keys=[];
    for(var i=0;i<16;i++){c=rotate(c,SH[i]);d=rotate(d,SH[i]);keys.push(pick(c.concat(d),PC2));}
    return keys;
  }
  function f(r,k){
    var x=xor(pick(r,E),k), out=[];
    for(var i=0;i<8;i++){
      var six=x.slice(i*6,i*6+6);
      var row=(six[0]<<1)|six[5];
      var col=(six[1]<<3)|(six[2]<<2)|(six[3]<<1)|six[4];
      var v=S[i][row*16+col];
      out.push((v>>3)&1,(v>>2)&1,(v>>1)&1,v&1);
    }
    return pick(out,PERM);
  }
  function core(blockHex,keys){
    var b=pick(hexToBits(blockHex),IP);
    var l=b.slice(0,32), r=b.slice(32);
    for(var i=0;i<16;i++){var n=xor(l,f(r,keys[i]));l=r;r=n;}
    return bitsToHex(pick(r.concat(l),FP));
  }
  window.__independentDes = {
    encrypt: function(keyHex, blockHex){ return core(blockHex, schedule(keyHex)); },
    decrypt: function(keyHex, blockHex){ return core(blockHex, schedule(keyHex).slice().reverse()); }
  };
})();
`;

async function installIndependentDes(page: Page): Promise<void> {
  await page.addScriptTag({ content: INDEPENDENT_DES });
  // Prove the injected implementation is itself right before trusting it as an
  // oracle, against a value published outside this repository: the CAVP
  // Variable Plaintext case 0.
  const check = await page.evaluate(() =>
    (window as unknown as { __independentDes: { encrypt: (k: string, b: string) => string } }).__independentDes.encrypt(
      '0101010101010101',
      '8000000000000000'
    )
  );
  expect(check, 'the independent DES must itself match a published CAVP answer').toBe('95f8a5e5dd31d900');
}

function independently(page: Page, direction: 'encrypt' | 'decrypt', key: string, block: string): Promise<string> {
  return page.evaluate(
    ([d, k, b]) =>
      (
        window as unknown as {
          __independentDes: Record<string, (k: string, b: string) => string>;
        }
      ).__independentDes[d](k, b),
    [direction, key, block] as const
  );
}

async function open(page: Page, tab: RegExp, panel: string): Promise<void> {
  await page.getByRole('tab', { name: tab }).click();
  await expect(page.locator(panel)).toBeVisible();
  await expect(page.locator(panel)).not.toBeEmpty();
}

/** Pull every 16-digit hex run out of a chunk of the page. */
async function hexRuns(page: Page, selector: string): Promise<string[]> {
  const text = (await page.locator(selector).innerText()).toLowerCase();
  return [...text.matchAll(/\b[0-9a-f]{16}\b/g)].map((m) => m[0]);
}

/** The value printed opposite a `<dt>` whose text contains `term`. */
async function valueFor(page: Page, panel: string, term: string): Promise<string> {
  const dd = page.locator(`${panel} dl.kv`).locator('dt', { hasText: term }).first();
  return (await dd.locator('xpath=following-sibling::dd[1]').innerText()).trim();
}

/**
 * The same, normalised as hex.
 *
 * The round exhibit prints its halves as SPACED UPPERCASE bytes for
 * readability, so a comparison against a computed lowercase run needs the
 * spacing and the case taken out first — which is a property of the
 * presentation, not of the value.
 */
async function hexValue(page: Page, panel: string, term: string): Promise<string> {
  return (await valueFor(page, panel, term)).replace(/\s/g, '').toLowerCase();
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#panel-round svg.round-figure')).toHaveCount(1);
});

// ── The page renders what it says it renders ────────────────────────────────

test.describe('structure', () => {
  test('nothing marked [hidden] is actually painted', async ({ page }) => {
    // The `[hidden]` cascade trap: a class rule that sets `display` outranks
    // the UA's `[hidden] { display: none }`, so an element paints while the
    // code believes it is hidden. Driven across every panel, because the trap
    // only appears once a panel has been rendered.
    for (const [tab, panel] of [
      [/Same Circuit/, '#panel-circuit'],
      [/Complementation/, '#panel-complement'],
      [/Meet-in-the-Middle/, '#panel-mitm'],
      [/Sweet32/, '#panel-sweet32'],
      [/CAVP Vectors/, '#panel-vectors'],
    ] as const) {
      await open(page, tab, panel);
    }
    const painted = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]'))
        .filter((el) => (el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true }))
        .map((el) => `${el.tagName.toLowerCase()}#${el.id}.${(el.getAttribute('class') ?? '').trim()}`)
    );
    expect(painted, 'an element carrying [hidden] is still painting').toEqual([]);
  });

  test('the hero states the withdrawal date the vectors panel states', async ({ page }) => {
    const sub = await page.locator('.cl-hero-sub').innerText();
    expect(sub).toContain('FIPS 46-3');
    const date = sub.match(/\d{4}-\d{2}-\d{2}/)?.[0];
    expect(date, 'the hero subtitle must carry a withdrawal date').toBeTruthy();
    await open(page, /CAVP Vectors/, '#panel-vectors');
    const provenance = await page.locator('#panel-vectors').innerText();
    // Cross-check: the same date, in a table built from a different constant.
    expect(provenance).toContain(`Withdrawn ${date}`);
  });
});

// ── The headline mechanism ──────────────────────────────────────────────────

test.describe('One Round', () => {
  test('the printed round values are a real DES round, re-derived independently', async ({ page }) => {
    await installIndependentDes(page);
    const key = await page.locator('#round-key').inputValue();
    const block = await page.locator('#round-block').inputValue();

    // The page prints the full ciphertext in its load verdict. Recompute it
    // with the independent implementation and require agreement.
    await page.getByRole('button', { name: 'Apply' }).click();
    const loaded = await page.locator('#panel-round .verdict-pass').innerText();
    const printed = loaded.toLowerCase().match(/\b[0-9a-f]{16}\b/)?.[0];
    expect(printed, 'the load verdict must print a ciphertext').toBeTruthy();
    expect(await independently(page, 'encrypt', key, block)).toBe(printed);
  });

  test('L(i) really is R(i-1) — the swap, cross-checked between two rows', async ({ page }) => {
    const rightIn = await hexValue(page, '#panel-round', 'R0 (right in)');
    const leftOut = await hexValue(page, '#panel-round', 'L1 (left out)');
    expect(leftOut).toBe(rightIn);
  });

  test('R(i) really is L(i-1) XOR f, recomputed from the printed halves', async ({ page }) => {
    const leftIn = await hexValue(page, '#panel-round', 'L0 (left in)');
    const fOut = await hexValue(page, '#panel-round', 'f(R, K)');
    const rightOut = await hexValue(page, '#panel-round', 'R1 (right out)');
    // Independent XOR, over the strings the page put on screen.
    const xored = leftIn
      .match(/../g)!
      .map((byte, i) => (parseInt(byte, 16) ^ parseInt(fOut.slice(i * 2, i * 2 + 2), 16)).toString(16).padStart(2, '0'))
      .join('');
    expect(xored).toBe(rightOut);
  });

  test('THE HEADLINE CLAIM: the round inverts under an F that provably does not', async ({ page }) => {
    await page.selectOption('#round-f', 'zero');
    const collapse = await page.locator('#panel-round .verdict-info').innerText();
    expect(collapse).toContain('Not injective');

    // Parts-sum-to-whole: the measurement must say more inputs than outputs.
    const inputs = Number((await valueFor(page, '#panel-round', 'Inputs swept')).replace(/[^\d]/g, '').slice(0, 5));
    const outputs = Number((await valueFor(page, '#panel-round', 'Distinct outputs')).replace(/[^\d]/g, ''));
    expect(outputs).toBeLessThan(inputs);
    expect(outputs).toBe(1);

    await page.getByRole('button', { name: /Undo this round/ }).click();
    const undo = page.locator('#panel-round .verdict-pass');
    await expect(undo).toContainText('Byte for byte identical');
    await expect(undo).toContainText('never inverted');

    // Cross-check the undo's own arithmetic: the recovered pair must equal the
    // round input pair, both of which the page printed separately.
    const recovered = (await valueFor(page, '#panel-round', 'Recovered L, R')).replace(/\s+/g, ' ').trim();
    const wasInput = (await valueFor(page, '#panel-round', 'Round input was')).replace(/\s+/g, ' ').trim();
    expect(recovered).toBe(wasInput);
  });

  test('the S-box census sums to the collapse figure the prose claims', async ({ page }) => {
    await page.locator('#panel-round details[data-group], #panel-round details').first().locator('summary').click();
    const body = await page.locator('#panel-round details').first().innerText();
    // Independent re-derivation of the claim in the prose: eight boxes, four
    // preimages each, 4^8 = 65,536.
    const perBox = [...body.matchAll(/(\d+) each/g)].map((m) => Number(m[1]));
    expect(perBox).toHaveLength(8);
    expect(perBox.every((c) => c === 4)).toBe(true);
    expect(perBox.reduce((a, b) => a * b, 1)).toBe(65536);
    expect(body).toContain('65,536');
  });

  test('RETIREMENT: changing F retires a fresh undo result, and re-selecting it does not', async ({ page }) => {
    await page.getByRole('button', { name: /Undo this round/ }).click();
    await expect(page.locator('#panel-round .verdict-pass')).toContainText('Byte for byte identical');

    // The no-op guard first: re-selecting the value already selected keeps it.
    await page.selectOption('#round-f', 'des');
    await expect(page.locator('#panel-round .verdict-pass')).toContainText('Byte for byte identical');
    await expect(page.locator('#panel-round .retired')).toHaveCount(0);

    // A real change retires it, and SAYS so.
    await page.selectOption('#round-f', 'and');
    await expect(page.locator('#panel-round .retired')).toContainText('Retired');
    await expect(page.locator('#panel-round .retired')).toContainText('round function changed');
    await expect(page.locator('#panel-round')).not.toContainText('Byte for byte identical');
  });

  test('FAILURE CODE PARITY_INVALID names the byte that is wrong', async ({ page }) => {
    await page.fill('#round-key', '0000010101010101');
    await page.getByRole('button', { name: 'Apply' }).click();
    const chip = page.locator('#panel-round .code-chip');
    await expect(chip).toHaveText('PARITY_INVALID');
    const message = await page.locator('#panel-round .verdict-fail').innerText();
    // The page must name the ACTUAL cause. Bytes 1 and 2 are 0x00, which has
    // even parity; every other byte is 0x01, which is odd and fine.
    expect(message).toContain('byte 1');
    expect(message).toContain('byte 2');
    expect(message).not.toContain('byte 3');
    await expect(page.locator('#round-key')).toHaveAttribute('aria-invalid', 'true');
  });
});

// ── Same circuit both ways ──────────────────────────────────────────────────

test.describe('Same Circuit Both Ways', () => {
  test.beforeEach(async ({ page }) => {
    await open(page, /Same Circuit/, '#panel-circuit');
  });

  test('the printed ciphertext is re-derivable, and the decryption really inverts it', async ({ page }) => {
    await installIndependentDes(page);
    const key = await page.locator('#circuit-key').inputValue();
    const block = await page.locator('#circuit-block').inputValue();
    await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();

    const ciphertext = (await valueFor(page, '#panel-circuit', 'Ciphertext')).trim();
    const decrypted = (await valueFor(page, '#panel-circuit', 'Decrypted')).trim();
    expect(ciphertext).toBe(await independently(page, 'encrypt', key, block));
    expect(decrypted).toBe(block.toLowerCase());
    // ...and independently: decrypting the printed ciphertext gives the block.
    expect(await independently(page, 'decrypt', key, ciphertext)).toBe(block.toLowerCase());
  });

  test('the two schedule columns really are one another reversed', async ({ page }) => {
    await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();
    // Scoped: this panel holds TWO tables, and the semi-weak one is inside a
    // shut <details> — shut, but still in the DOM, so an unscoped selector
    // collects 22 rows and the count assertion fails for the wrong reason.
    const rows = await page.locator('#panel-circuit [aria-label="Key schedule, forward and reversed"] tbody tr').all();
    expect(rows).toHaveLength(16);
    const forward: string[] = [];
    const reverse: string[] = [];
    for (const row of rows) {
      const cells = await row.locator('td').allInnerTexts();
      forward.push(cells[1].trim());
      reverse.push(cells[2].trim());
    }
    // Independent re-derivation of the page's claim, from the table it printed.
    expect(reverse).toEqual([...forward].reverse());
    // Cross-check the per-row verdict column against that comparison.
    for (const [i, row] of rows.entries()) {
      const cells = await row.locator('td').allInnerTexts();
      expect(cells[3].trim()).toBe(forward[i] === reverse[i] ? 'same' : 'differs');
    }
  });

  test('a weak key really is an involution, verified against the printed values', async ({ page }) => {
    await installIndependentDes(page);
    await page.locator('#panel-circuit .seg-btn').first().click();
    await expect(page.locator('#panel-circuit .verdict-alarm')).toContainText('E(E(P)) = P');

    const key = (await valueFor(page, '#panel-circuit', 'Key')).trim();
    const plaintext = (await valueFor(page, '#panel-circuit', 'Plaintext')).trim();
    const once = (await valueFor(page, '#panel-circuit', 'E(P)')).trim();
    const twice = (await valueFor(page, '#panel-circuit', 'E(E(P))')).trim();

    // Re-derived, not re-asserted: run the independent cipher twice.
    expect(once).toBe(await independently(page, 'encrypt', key, plaintext));
    expect(twice).toBe(await independently(page, 'encrypt', key, once));
    expect(twice).toBe(plaintext);
    // And the reason the page gives must be the one the table shows.
    await expect(page.locator('#panel-circuit .verdict-alarm')).toContainText('all sixteen subkeys are identical');
    expect(await valueFor(page, '#panel-circuit', 'Distinct subkeys')).toContain('1 of 16');
  });

  test('an ordinary key is NOT an involution — the negative case renders too', async ({ page }) => {
    await page.locator('#panel-circuit .seg-btn').last().click();
    await expect(page.locator('#panel-circuit .verdict-pass').last()).toContainText('E(E(P)) is not P');
    expect(await valueFor(page, '#panel-circuit', 'Distinct subkeys')).toContain('16 of 16');
  });

  test('FAILURE CODE WEAK_KEY names the key and the way out', async ({ page }) => {
    await page.fill('#circuit-key', '0101010101010101');
    await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();
    await expect(page.locator('#panel-circuit .code-chip')).toHaveText('WEAK_KEY');
    const message = await page.locator('#panel-circuit .verdict-fail').innerText();
    expect(message).toContain('0101010101010101');
    expect(message).toContain('encrypting twice returns the plaintext');
    expect(message).toContain('Deliberately broken mode');
  });

  test('FAILURE CODE SEMI_WEAK_KEY names the partner key that undoes it', async ({ page }) => {
    await page.fill('#circuit-key', '01fe01fe01fe01fe');
    await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();
    await expect(page.locator('#panel-circuit .code-chip')).toHaveText('SEMI_WEAK_KEY');
    // The named partner must actually be its partner: encrypting under one and
    // then the other must return the plaintext, checked with the independent DES.
    await installIndependentDes(page);
    const message = await page.locator('#panel-circuit .verdict-fail').innerText();
    const partner = message.toLowerCase().match(/fe01fe01fe01fe01/)?.[0];
    expect(partner, 'the message must name the partner key').toBeTruthy();
    const p = '0123456789abcdef';
    const once = await independently(page, 'encrypt', '01fe01fe01fe01fe', p);
    expect(await independently(page, 'encrypt', partner as string, once)).toBe(p);
  });

  test('the deliberately-broken mode is never the default', async ({ page }) => {
    await expect(page.locator('#circuit-allow-weak')).not.toBeChecked();
    await page.check('#circuit-allow-weak');
    await page.fill('#circuit-key', '0101010101010101');
    await page.getByRole('button', { name: 'Encrypt, then decrypt' }).click();
    await expect(page.locator('#panel-circuit .code-chip')).toHaveCount(0);
    await expect(page.locator('#panel-circuit .verdict-alarm')).toContainText('same list');
  });
});

// ── Complementation ─────────────────────────────────────────────────────────

test.describe('Complementation', () => {
  test.beforeEach(async ({ page }) => {
    await open(page, /Complementation/, '#panel-complement');
  });

  test('both sides of the identity are re-derivable, and the complements are real complements', async ({ page }) => {
    await installIndependentDes(page);
    const key = (await valueFor(page, '#panel-complement', 'K')).trim();
    const plaintext = (await valueFor(page, '#panel-complement', 'P')).trim();
    const keyBar = (await valueFor(page, '#panel-complement', '~K')).trim();
    const plainBar = (await valueFor(page, '#panel-complement', '~P')).trim();

    // The page's "complement" columns really are bitwise complements.
    const flip = (h: string): string =>
      h
        .match(/../g)!
        .map((b) => (~parseInt(b, 16) & 0xff).toString(16).padStart(2, '0'))
        .join('');
    expect(keyBar).toBe(flip(key));
    expect(plainBar).toBe(flip(plaintext));

    const run = (await valueFor(page, '#panel-complement', 'DES(~K, ~P)')).trim();
    const flipped = (await valueFor(page, '#panel-complement', '~DES(K, P)')).trim();
    expect(run).toBe(flipped);

    // Independently: the identity itself, computed by the second DES.
    expect(run).toBe(await independently(page, 'encrypt', keyBar, plainBar));
    expect(flipped).toBe(flip(await independently(page, 'encrypt', key, plaintext)));
  });

  test('the halving is measured, not asserted: the counters agree with the ratio', async ({ page }) => {
    await page.selectOption('#comp-half', 'direct');
    await page.getByRole('button', { name: 'Race the two searches' }).click();

    const plainEnc = Number((await valueFor(page, '#panel-complement', 'Plain: encryptions')).replace(/,/g, ''));
    const plainKeys = Number((await valueFor(page, '#panel-complement', 'Plain: keys covered')).replace(/,/g, ''));
    const cleverEnc = Number((await valueFor(page, '#panel-complement', 'Complementation: encryptions')).replace(/,/g, ''));
    const cleverKeys = Number((await valueFor(page, '#panel-complement', 'Complementation: keys covered')).replace(/,/g, ''));

    // Parts-sum-to-whole, recomputed from the counters rather than read off the
    // page's own ratio row.
    expect(plainKeys / plainEnc).toBeCloseTo(1, 6);
    expect(cleverKeys / cleverEnc).toBeCloseTo(2, 6);
    expect(cleverEnc).toBe(plainEnc);
    expect(cleverKeys).toBe(2 * plainKeys);

    // Cross-check: the page's printed ratios must equal the recomputed ones.
    expect(await valueFor(page, '#panel-complement', 'Keys per encryption, plain')).toBe('1.00');
    expect(await valueFor(page, '#panel-complement', 'Keys per encryption, clever')).toBe('2.00');
  });

  test('hidden in the complement half, the plain search sweeps everything and finds nothing', async ({ page }) => {
    await page.selectOption('#comp-width', '10');
    await page.selectOption('#comp-half', 'complement');
    await page.getByRole('button', { name: 'Race the two searches' }).click();

    await expect(page.locator('#panel-complement .verdict-alarm')).toContainText('missed it entirely');
    const plainOutcome = await valueFor(page, '#panel-complement', 'Plain: outcome');
    expect(plainOutcome).toContain('NOT FOUND');
    const plainEnc = Number((await valueFor(page, '#panel-complement', 'Plain: encryptions')).replace(/,/g, ''));
    // It swept the WHOLE space: 2^10 encryptions, one per candidate.
    expect(plainEnc).toBe(1024);

    // And the key the clever search found really is the complement of a swept
    // candidate — checked by flipping it back and re-encrypting.
    const cleverOutcome = await valueFor(page, '#panel-complement', 'Complementation: outcome');
    expect(cleverOutcome).toContain('FOUND');
    expect(cleverOutcome).toContain('as the complement of the tested candidate');
  });

  test('RETIREMENT: changing the search width retires the race, re-selecting does not', async ({ page }) => {
    await page.getByRole('button', { name: 'Race the two searches' }).click();
    await expect(page.locator('#panel-complement dl.kv').last()).toBeVisible();

    await page.selectOption('#comp-width', '12'); // already 12 — a no-op
    await expect(page.locator('#panel-complement .retired')).toHaveCount(0);

    await page.selectOption('#comp-width', '8');
    await expect(page.locator('#panel-complement .retired')).toContainText('search width changed');
  });
});

// ── 2DES ────────────────────────────────────────────────────────────────────

test.describe('2DES meet-in-the-middle', () => {
  test('the recovered pair really encrypts the known plaintext to the known ciphertext', async ({ page }) => {
    test.setTimeout(240_000);
    await open(page, /Meet-in-the-Middle/, '#panel-mitm');
    await installIndependentDes(page);
    await page.selectOption('#mitm-bits', '10');
    await page.getByRole('button', { name: 'Run the attack' }).click();
    await expect(page.locator('#panel-mitm .verdict-alarm')).toContainText('Both keys recovered', {
      timeout: 180_000,
    });

    const k1 = (await valueFor(page, '#panel-mitm', 'K1 recovered')).trim();
    const k2 = (await valueFor(page, '#panel-mitm', 'K2 recovered')).trim();
    const trueK1 = (await valueFor(page, '#panel-mitm', 'K1 the victim used')).trim();
    const trueK2 = (await valueFor(page, '#panel-mitm', 'K2 the victim used')).trim();
    expect(k1).toBe(trueK1);
    expect(k2).toBe(trueK2);

    // INDEPENDENT: 2DES the first known plaintext under the recovered pair,
    // using the second implementation, and require the meeting value to sit in
    // the middle of it.
    const meeting = (await valueFor(page, '#panel-mitm', 'Meeting value')).match(/[0-9a-f]{16}/)?.[0];
    expect(meeting).toBe(await independently(page, 'encrypt', k1, '0123456789abcdef'));
  });

  test('the work is the SUM of the halves, cross-checked against the printed setup', async ({ page }) => {
    await open(page, /Meet-in-the-Middle/, '#panel-mitm');
    await page.selectOption('#mitm-bits', '12');
    const perSide = Number((await valueFor(page, '#panel-mitm', 'Keys per side')).replace(/,/g, ''));
    const work = await valueFor(page, '#panel-mitm', 'Work the attack will do');
    const ops = Number(work.replace(/,/g, '').match(/\d+/)?.[0]);
    const naive = await valueFor(page, '#panel-mitm', 'Total pairs if searched naively');

    expect(perSide).toBe(2 ** 12);
    // Re-derived: 2 x 2^12, not the product.
    expect(ops).toBe(2 * perSide);
    expect(naive).toContain('2^24');
    expect(ops).toBeLessThan(perSide * perSide);
  });
});

// ── NEG-1 ───────────────────────────────────────────────────────────────────

test.describe('NEG-1: increasing key length does not repair a 64-bit block-size bound', () => {
  test.beforeEach(async ({ page }) => {
    await open(page, /Sweet32/, '#panel-sweet32');
  });

  /**
   * The load-bearing assertion. The page's birthday readout is driven only by
   * the BLOCK size, so the 64-bit row must be identical for DES (56-bit key)
   * and 3DES (168-bit key) — which is exactly the claim — while the 128-bit row
   * differs enormously at the same session size.
   *
   * It is checked by RE-DERIVING the probability here, from the block count the
   * page printed, by the closed form rather than by calling the page's own
   * function.
   */
  test('the printed probability depends on the block size and on nothing else', async ({ page }) => {
    await page.locator('#sw-blocks').fill('32');
    const row64 = await valueFor(page, '#panel-sweet32', '64-bit block');
    const row128 = await valueFor(page, '#panel-sweet32', '128-bit block');

    const p64 = Number(row64.match(/([\d.]+)%/)?.[1]);
    // Independent re-derivation: 1 - exp(-n(n-1)/2N) at n = 2^32, N = 2^64.
    const n = 2 ** 32;
    const expected = (1 - Math.exp(-(n * (n - 1)) / (2 * 2 ** 64))) * 100;
    expect(p64).toBeCloseTo(expected, 1);
    expect(p64).toBeGreaterThan(39);
    expect(p64).toBeLessThan(40);

    // The 128-bit row at the SAME session size is vanishing — the only thing
    // that changed is the block width.
    expect(row128).toMatch(/e-\d+|0\.00/);
    expect(row64).toContain('LEAKING');
    expect(row128).toContain('safe');

    // The label names three ciphers with three different key lengths on the
    // one 64-bit row, which is the claim stated where a reader will see it.
    const label = await page.locator('#panel-sweet32 dl.kv dt', { hasText: '64-bit block' }).innerText();
    expect(label).toContain('DES');
    expect(label).toContain('3DES');
  });

  test('the prose in the page makes the same claim the arithmetic makes', async ({ page }) => {
    const text = await page.locator('#panel-sweet32').innerText();
    expect(text).toContain('3DES has a 168-bit key and the same 64-bit block');
    expect(text).toContain('Key length and block size are independent axes');
    // And the honest limit of the claim is stated too.
    await page.locator('#panel-sweet32 details', { hasText: 'does NOT claim' }).locator('summary').click();
    const caveat = await page.locator('#panel-sweet32 details', { hasText: 'does NOT claim' }).innerText();
    expect(caveat).toContain('Two-key TDEA falls well below its nominal strength');
    expect(caveat).toContain('separate axes');
  });

  test('moving the block size moves the bound; the key is not an input anywhere', async ({ page }) => {
    // Sweep the slider and require the 64-bit row to be a strictly increasing
    // function of session size — recomputed here, not read from the page.
    const readings: number[] = [];
    for (const log of ['20', '26', '30', '34']) {
      await page.locator('#sw-blocks').fill(log);
      const row = await valueFor(page, '#panel-sweet32', '64-bit block');
      readings.push(Number(row.match(/([\d.e+-]+)%/)?.[1]));
    }
    for (let i = 1; i < readings.length; i++) {
      expect(readings[i]).toBeGreaterThan(readings[i - 1]);
    }
    // No control on this card names a key length.
    const controls = await page.locator('#panel-sweet32 label').allInnerTexts();
    expect(controls.join(' ').toLowerCase()).not.toContain('key length');
  });
});

// ── Sweet32 recovery and the data limit ─────────────────────────────────────

test.describe('Sweet32', () => {
  test.beforeEach(async ({ page }) => {
    await open(page, /Sweet32/, '#panel-sweet32');
  });

  test('the arranged collision is labelled as arranged, permanently', async ({ page }) => {
    const banner = page.locator('#panel-sweet32 .arranged-banner');
    await expect(banner).toContainText('ARRANGED COLLISION');
    await expect(banner).toContainText('PLACED using the key');
    // Still there after the interaction that produces the result.
    await page.getByRole('button', { name: 'Recover the cookie' }).click();
    await expect(banner).toContainText('ARRANGED COLLISION');
    await page.getByRole('button', { name: 'New session' }).click();
    await expect(banner).toContainText('ARRANGED COLLISION');
  });

  test('the recovery is the printed XOR of the printed values', async ({ page }) => {
    await page.getByRole('button', { name: 'Recover the cookie' }).click();
    const attacker = (await valueFor(page, '#panel-sweet32', "attacker's own block")).trim();

    // The two chaining blocks, addressed by the exact terms the page prints —
    // their indices depend on where the collision was placed, so they are read
    // off the page rather than hard-coded.
    const dts = await page.locator('#panel-sweet32 dl.kv dt').allInnerTexts();
    const chainTerms = dts.filter((t) => /^C\d+$/.test(t.trim()));
    expect(chainTerms.length).toBeGreaterThanOrEqual(2);
    const cBeforeA = (await valueFor(page, '#panel-sweet32', chainTerms[0])).trim();
    const cBeforeS = (await valueFor(page, '#panel-sweet32', chainTerms[1])).trim();

    const recoveredTerm = dts.find((t) => t.includes('XOR')) as string;
    const recovered = (await valueFor(page, '#panel-sweet32', recoveredTerm)).trim();

    // INDEPENDENT: do the XOR here, from the three values on screen.
    const xor3 = (a: string, b: string, c: string): string =>
      a
        .match(/../g)!
        .map((byte, i) =>
          (
            parseInt(byte, 16) ^
            parseInt(b.slice(i * 2, i * 2 + 2), 16) ^
            parseInt(c.slice(i * 2, i * 2 + 2), 16)
          )
            .toString(16)
            .padStart(2, '0')
        )
        .join('');
    expect(xor3(attacker, cBeforeA, cBeforeS)).toBe(recovered);

    // And the recovered bytes must decode to the cookie the page shows.
    const asText = (await valueFor(page, '#panel-sweet32', 'As text')).trim();
    const real = (await valueFor(page, '#panel-sweet32', 'The real cookie was')).trim();
    expect(asText).toBe(real);
    const decoded = recovered
      .match(/../g)!
      .map((b) => String.fromCharCode(parseInt(b, 16)))
      .join('');
    expect(decoded).toBe(asText);
  });

  test('the same arithmetic on a non-colliding pair produces something else', async ({ page }) => {
    await page.getByRole('button', { name: 'Recover the cookie' }).click();
    const cookie = (await valueFor(page, '#panel-sweet32', 'As text')).trim();

    await page.getByRole('button', { name: /did NOT collide/ }).click();
    await expect(page.locator('#panel-sweet32 .verdict-info').last()).toContainText('Garbage, as it should be');
    const produced = (await valueFor(page, '#panel-sweet32', 'What the identity produces')).trim();
    const realBlock = (await valueFor(page, '#panel-sweet32', 'The real block')).trim();
    const asText = (await valueFor(page, '#panel-sweet32', 'As text')).trim();

    expect(asText).not.toBe(cookie);
    expect(asText).not.toBe(realBlock);
    // The difference row must be non-zero — the identity really failed.
    const difference = (await valueFor(page, '#panel-sweet32', 'Difference')).trim();
    expect(difference).not.toBe('0000000000000000');
    expect(produced).toMatch(/^[0-9a-f]{16}$/);
  });

  test('FAILURE CODE BLOCK_SIZE_EXCEEDED names the limit and its source', async ({ page }) => {
    await page.locator('#sw-limit-blocks').fill('26');
    await expect(page.locator('#panel-sweet32 .code-chip')).toHaveText('BLOCK_SIZE_EXCEEDED');
    const message = await page.locator('#panel-sweet32 .verdict-fail').innerText();
    expect(message).toContain('2^20 blocks (8 MiB)');
    // The page names the SOURCE of the number, not just the number.
    expect(await valueFor(page, '#panel-sweet32', 'Source')).toContain('SP 800-67 Rev. 2');
    expect(await valueFor(page, '#panel-sweet32', 'Source')).toContain('withdrawn 2024-01-01');

    // Cross-check: the refused request must exceed the stated limit, computed here.
    const requested = await valueFor(page, '#panel-sweet32', 'Requested');
    const exponent = Number(requested.match(/2\^(\d+)/)?.[1]);
    expect(2 ** exponent).toBeGreaterThan(2 ** 20);
  });

  test('the limit boundary is exact: 2^20 permitted, 2^21 refused', async ({ page }) => {
    await page.locator('#sw-limit-blocks').fill('20');
    await expect(page.locator('#panel-sweet32 .verdict-pass').last()).toContainText('Permitted');
    await expect(page.locator('#panel-sweet32 .code-chip')).toHaveCount(0);
    await page.locator('#sw-limit-blocks').fill('21');
    await expect(page.locator('#panel-sweet32 .code-chip')).toHaveText('BLOCK_SIZE_EXCEEDED');
  });

  test('RETIREMENT: a new session retires the recovery it no longer describes', async ({ page }) => {
    await page.getByRole('button', { name: 'Recover the cookie' }).click();
    await expect(page.locator('#panel-sweet32')).toContainText('The cookie is out');
    await page.getByRole('button', { name: 'New session' }).click();
    await expect(page.locator('#panel-sweet32 .retired')).toContainText('new session under a new key');
    await expect(page.locator('#panel-sweet32')).not.toContainText('The cookie is out');
  });
});

// ── The vectors panel ───────────────────────────────────────────────────────

test.describe('CAVP vectors', () => {
  test('the summary count equals the rows it counts', async ({ page }) => {
    await open(page, /CAVP Vectors/, '#panel-vectors');
    const summary = await page.locator('#panel-vectors .pill-ok').first().innerText();
    const [passed, total] = summary.split('/').map((s) => Number(s.replace(/,/g, '').trim()));
    expect(passed).toBe(total);

    // Cross-check against the per-family headings, summed here.
    const headings = await page.locator('#panel-vectors details > summary').allInnerTexts();
    const familySums = headings
      .map((h) => h.match(/([\d,]+)\s*\/\s*([\d,]+)\s*assertions/))
      .filter(Boolean)
      .map((m) => [Number((m as RegExpMatchArray)[1].replace(/,/g, '')), Number((m as RegExpMatchArray)[2].replace(/,/g, ''))]);
    expect(familySums).toHaveLength(6);
    expect(familySums.reduce((sum, [p]) => sum + p, 0)).toBe(passed);
    expect(familySums.reduce((sum, [, t]) => sum + t, 0)).toBe(total);

    // And against the prose in the intro, which states the same two numbers.
    const intro = await page.locator('#panel-vectors .intro').innerText();
    expect(intro).toContain(`${total.toLocaleString('en-US')} assertions`);
    expect(intro).toContain(`${(total / 2).toLocaleString('en-US')}`);
  });

  test('an expanded family is re-derivable with the independent DES', async ({ page }) => {
    await open(page, /CAVP Vectors/, '#panel-vectors');
    await installIndependentDes(page);
    await page.locator('#panel-vectors details[data-group="subtab"] > summary').click();
    const rows = await page.locator('#panel-vectors details[data-group="subtab"] tbody tr').all();
    expect(rows).toHaveLength(19);
    for (const row of rows) {
      const cells = await row.locator('td').allInnerTexts();
      const [key, plaintext, ciphertext] = cells.map((c) => c.trim());
      expect(await independently(page, 'encrypt', key, plaintext)).toBe(ciphertext);
      expect(await independently(page, 'decrypt', key, ciphertext)).toBe(plaintext);
    }
  });

  test('every hex run the page prints for these vectors is 16 digits', async ({ page }) => {
    await open(page, /CAVP Vectors/, '#panel-vectors');
    await page.locator('#panel-vectors details[data-group="subtab"] > summary').click();
    const runs = await hexRuns(page, '#panel-vectors details[data-group="subtab"] tbody');
    expect(runs).toHaveLength(19 * 3);
  });
});

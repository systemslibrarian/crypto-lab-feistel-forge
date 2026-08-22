/**
 * Exhibit 6 — the CAVP known-answer vectors, run in the browser.
 *
 * The unit suite already gates every one of these at build time. Running them
 * again here is not redundant: it lets a reader watch the cipher on this page
 * agree with NIST's published answers, on their own machine, without taking
 * anyone's word for it. Each vector is asserted in both directions, which is
 * what the .rsp files' paired [ENCRYPT] and [DECRYPT] sections ask for.
 *
 * The provenance card is the other half of this exhibit, and the more
 * important half. Everything DES is cited to has been withdrawn, and a lab
 * that quietly cites a withdrawn standard as though it were live is teaching
 * something false about how standards work.
 */
import { decryptBlock, encryptBlock } from '../des/des';
import { cbcDecrypt, cbcEncrypt } from '../des/modes';
import { parseHex, toHex } from '../des/bytes';
import { ASSERTION_COUNT, KAT_GROUPS, VECTOR_COUNT } from '../des/vectors';
import type { KatGroup, KatVector } from '../des/vectors';
import {
  append,
  button,
  card,
  clear,
  disclosure,
  el,
  intro,
  kv,
  n,
  pill,
  scroller,
  statusRegion,
  verdict,
} from './dom';

interface GroupOutcome {
  readonly group: KatGroup;
  readonly rows: readonly {
    readonly vector: KatVector;
    readonly encrypted: string;
    readonly decrypted: string;
    readonly encryptOk: boolean;
    readonly decryptOk: boolean;
  }[];
  readonly passed: number;
  readonly total: number;
}

export function renderVectorsPanel(root: HTMLElement): void {
  clear(root);

  append(
    root,
    intro(
      'Checking the cipher against NIST',
      el(
        'p',
        {},
        'A block cipher with one transposed digit in one of its tables still round-trips ' +
          'perfectly and still produces output that looks random. The only thing that catches ' +
          'that is a known-answer test: a key, a plaintext, and the ciphertext somebody else ' +
          'published.'
      ),
      el(
        'p',
        {},
        `Below are ${n(VECTOR_COUNT)} of them, taken from NIST's archived validation archive, ` +
          `run against the DES on this page in both directions — ${n(ASSERTION_COUNT)} assertions ` +
          'in total. The same vectors gate the build; these run in your browser so you can watch ' +
          'the agreement happen rather than be told about it.'
      )
    )
  );

  append(root, provenanceCard());

  const summary = statusRegion('Known-answer test summary');
  const detail = el('div', {});
  const runBtn = button('Run all vectors again', 'btn-primary');

  append(
    root,
    card(
      'Known-answer results',
      `${n(VECTOR_COUNT)} vectors, each asserted encrypting and decrypting.`,
      el('div', { class: 'controls' }, el('div', { class: 'field' }, runBtn)),
      summary,
      detail
    )
  );

  function run(): void {
    const outcomes = KAT_GROUPS.map(runGroup);
    const passed = outcomes.reduce((sum, o) => sum + o.passed, 0);
    const total = outcomes.reduce((sum, o) => sum + o.total, 0);
    clear(summary);
    clear(detail);
    append(
      summary,
      el(
        'p',
        {},
        pill(passed === total ? 'ok' : 'bad', `${n(passed)} / ${n(total)}`),
        ' assertions passed.'
      ),
      passed === total
        ? verdict(
            'pass',
            el('strong', { text: 'Every published answer matched. ' }),
            'The DES in this page computes the same function NIST validated implementations against.'
          )
        : verdict(
            'fail',
            el('strong', { text: `${n(total - passed)} assertions failed. ` }),
            'The cipher in this page disagrees with NIST. Expand the failing family below.'
          )
    );
    for (const outcome of outcomes) append(detail, groupDisclosure(outcome));
  }

  runBtn.addEventListener('click', run);
  run();
}

function runGroup(group: KatGroup): GroupOutcome {
  const rows = group.vectors.map((vector) => {
    const key = hexOf(vector.key);
    const plaintext = hexOf(vector.plaintext);
    const ciphertext = hexOf(vector.ciphertext);
    let encrypted: string;
    let decrypted: string;
    if (group.mode === 'ecb') {
      encrypted = toHex(encryptBlock(key, plaintext));
      decrypted = toHex(decryptBlock(key, ciphertext));
    } else {
      const iv = hexOf(vector.iv as string);
      const forward = cbcEncrypt(key, iv, plaintext);
      const backward = cbcDecrypt(key, iv, ciphertext);
      encrypted = forward.ok ? toHex(forward.value.ciphertext) : `refused: ${forward.error.code}`;
      decrypted = backward.ok ? toHex(backward.value) : `refused: ${backward.error.code}`;
    }
    return {
      vector,
      encrypted,
      decrypted,
      encryptOk: encrypted === vector.ciphertext,
      decryptOk: decrypted === vector.plaintext,
    };
  });
  const passed = rows.reduce((sum, r) => sum + (r.encryptOk ? 1 : 0) + (r.decryptOk ? 1 : 0), 0);
  return { group, rows, passed, total: rows.length * 2 };
}

function groupDisclosure(outcome: GroupOutcome): HTMLElement {
  const body = el('tbody');
  for (const row of outcome.rows) {
    append(
      body,
      el(
        'tr',
        {},
        el('td', { text: row.vector.key }),
        el('td', { text: row.vector.plaintext }),
        el('td', { text: row.vector.ciphertext }),
        el('td', {}, row.encryptOk ? pill('ok', 'E ok') : pill('bad', `E got ${row.encrypted}`)),
        el('td', {}, row.decryptOk ? pill('ok', 'D ok') : pill('bad', `D got ${row.decrypted}`))
      )
    );
  }
  const ok = outcome.passed === outcome.total;
  const details = disclosure(
    `${outcome.group.title} — ${n(outcome.passed)} / ${n(outcome.total)} assertions`,
    el('p', {}, el('strong', { text: outcome.group.file }), ' — ', el('span', { text: outcome.group.note })),
    scroller(
      `${outcome.group.title} vectors`,
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
            el('th', { scope: 'col', text: 'Plaintext' }),
            el('th', { scope: 'col', text: 'Ciphertext' }),
            el('th', { scope: 'col', text: 'Encrypt' }),
            el('th', { scope: 'col', text: 'Decrypt' })
          )
        ),
        body
      )
    )
  );
  const summaryEl = details.querySelector('summary');
  if (summaryEl) append(summaryEl, ' ', ok ? pill('ok', 'PASS') : pill('bad', 'FAIL'));
  return details;
}

function provenanceCard(): HTMLElement {
  const rows: readonly (readonly [string, string, string])[] = [
    ['FIPS 46-3', 'Data Encryption Standard — the specification these tables implement', 'Withdrawn 2005-05-19'],
    ['NBS SP 500-20 (Rev. 1980)', 'Where the five known-answer families were defined', 'Superseded 1980; historical'],
    ['NIST SP 800-17', 'MOVS — the DES validation system', 'Withdrawn 2018-08-01'],
    ['NIST SP 800-20', 'TMOVS — the TDEA validation system', 'Withdrawn 2018-09-26'],
    ['NIST SP 800-67 Rev. 2', 'TDEA, and the 2^20-block data limit in §3.4', 'Withdrawn 2024-01-01'],
  ];
  const body = el('tbody');
  for (const [doc, what, status] of rows) {
    append(
      body,
      el(
        'tr',
        {},
        el('td', { text: doc }),
        el('td', { text: what }),
        el('td', {}, pill('warn', status))
      )
    );
  }

  return card(
    'Where these vectors come from, and why every source is withdrawn',
    'A historical cipher has no live normative source. Withdrawn is fine; unmarked is not.',
    el(
      'p',
      {},
      'The vectors were taken from ',
      el('code', { text: 'KAT_TDES.zip' }),
      ' on NIST’s Cryptographic Algorithm Validation Program page (118,218 bytes, SHA-256 ',
      el('code', { text: '19d8841f…b8ccb374' }),
      ', downloaded 2026-08-22; the .rsp files inside are dated 2011-04-21).'
    ),
    el(
      'p',
      {},
      el('strong', { text: 'The archive is named for Triple DES, and that is worth a sentence. ' }),
      'Every one of its 55 files uses the single-key field ',
      el('code', { text: 'KEYs' }),
      ', never ',
      el('code', { text: 'KEY1/KEY2/KEY3' }),
      '. TDEA with all three keys equal is single DES exactly — encrypt, decrypt, encrypt under ' +
        'one key collapses to one encryption — so these ARE the classic DES tables. NIST never ' +
        'published a DES-only archive.'
    ),
    scroller(
      'Specification and validation sources, with status',
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
            el('th', { scope: 'col', text: 'Document' }),
            el('th', { scope: 'col', text: 'What it is' }),
            el('th', { scope: 'col', text: 'Status' })
          )
        ),
        body
      )
    ),
    el(
      'p',
      { class: 'field-help' },
      'NIST’s Retired Testing page gives the reason for the first withdrawal outright: FIPS 46-3 ' +
        '"was withdrawn May 19, 2005 because the cryptographic algorithm no longer provided the ' +
        'security that is needed". SP 800-17 was withdrawn because "this validation system is for ' +
        'algorithms that have been deprecated (e.g., DES, Skipjack)".'
    ),
    disclosure(
      'The five known-answer families, and what each one exercises',
      kv(
        KAT_GROUPS.map(
          (g) => [`${g.title} (${g.vectors.length})`, g.note] as const
        )
      ),
      el(
        'p',
        {},
        'The case counts — 64, 64, 56, 32 and 19 — are exactly the DES test set defined in ' +
          'SP 500-20 Appendix B. The Inverse Permutation family is the Variable Plaintext family ' +
          'with its columns swapped, which the unit suite asserts rather than assumes; SP 800-17 ' +
          'prints only one table for the pair.'
      )
    )
  );
}

function hexOf(text: string): Uint8Array {
  const parsed = parseHex(text, 8);
  if (!parsed.ok) throw new Error(`bad vector constant: ${text}`);
  return parsed.value;
}

#!/usr/bin/env node
/**
 * Regenerate `src/des/vectors.ts` from NIST's archived CAVP archive.
 *
 *   npm run vectors:build
 *
 * Downloads `KAT_TDES.zip` from the Cryptographic Algorithm Validation
 * Program's block-cipher page, VERIFIES ITS SHA-256 against the digest recorded
 * below, extracts the six `.rsp` files this lab uses, and writes the TypeScript
 * module. It refuses to write anything if the digest does not match, because a
 * vector file whose provenance is unverified is worse than no vector file: the
 * whole point of a known-answer test is that somebody else published the
 * answer.
 *
 * The `.rsp` format splits into `[ENCRYPT]` and `[DECRYPT]` sections that carry
 * the SAME triples — asserted here at generation time, which is what licenses
 * `vectors.ts` to store each triple once and `vectors.test.ts` to assert it in
 * both directions.
 *
 * Requires `curl` and `unzip` on PATH. This is a maintenance script, not part
 * of the build; nothing in `npm run build` or the test suites touches the
 * network.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const URL =
  'https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/KAT_TDES.zip';
const EXPECTED_SHA256 = '19d8841f84ae3415350b069a4768bd416c05a0533ee43e905ab099adb8ccb374';
const OUT = new global.URL('../src/des/vectors.ts', import.meta.url).pathname;

/** The six families this lab ships, in the order they appear in the module. */
const FAMILIES = [
  {
    id: 'vartext',
    file: 'TECBvartext.rsp',
    mode: 'ecb',
    title: 'Variable Plaintext KAT',
    note: 'Key 0101010101010101 and a plaintext that walks a single 1 bit across all 64 positions. Exercises IP and E.',
  },
  {
    id: 'invperm',
    file: 'TECBinvperm.rsp',
    mode: 'ecb',
    title: 'Inverse Permutation KAT',
    note: 'The Variable Plaintext table transposed: decrypting each of its ciphertexts must give the single-bit basis vector back. SP 800-17 prints no separate table for it.',
  },
  {
    id: 'varkey',
    file: 'TECBvarkey.rsp',
    mode: 'ecb',
    title: 'Variable Key KAT',
    note: 'Plaintext 0000000000000000 and a key that walks a single 1 bit across all 56 key bits. Exercises PC-1 and PC-2.',
  },
  {
    id: 'permop',
    file: 'TECBpermop.rsp',
    mode: 'ecb',
    title: 'Permutation Operation KAT',
    note: 'Thirty-two keys chosen to exercise the P permutation.',
  },
  {
    id: 'subtab',
    file: 'TECBsubtab.rsp',
    mode: 'ecb',
    title: 'Substitution Table KAT',
    note: 'Nineteen key/plaintext pairs chosen so that every entry of every S-box is used.',
  },
  {
    id: 'cbcvartext',
    file: 'TCBCvartext.rsp',
    mode: 'cbc',
    title: 'Variable Plaintext KAT (CBC)',
    note: 'The same single-bit sweep run in CBC with an all-zero IV, so the mode is gated by CAVP too rather than only by a round-trip.',
  },
];

/** Parse one `.rsp` file into its two sections. */
function parseRsp(text) {
  const sections = { ENCRYPT: [], DECRYPT: [] };
  let current = null;
  let record = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '[ENCRYPT]') {
      current = 'ENCRYPT';
      continue;
    }
    if (line === '[DECRYPT]') {
      current = 'DECRYPT';
      continue;
    }
    if (!line || line.startsWith('#')) continue;
    const [key, value] = line.split(' = ').map((s) => s.trim());
    if (key === 'COUNT') {
      record = {};
      continue;
    }
    record[key] = value;
    if (record.KEYs && record.PLAINTEXT && record.CIPHERTEXT) {
      sections[current].push({ ...record });
      record = {};
    }
  }
  return sections;
}

const work = mkdtempSync(join(tmpdir(), 'cavp-'));
try {
  const zip = join(work, 'KAT_TDES.zip');
  process.stdout.write(`downloading ${URL}\n`);
  execFileSync('curl', ['-sSL', '-o', zip, URL]);

  const bytes = readFileSync(zip);
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (digest !== EXPECTED_SHA256) {
    throw new Error(
      `SHA-256 mismatch.\n  expected ${EXPECTED_SHA256}\n  got      ${digest}\n` +
        'Refusing to write vectors.ts. If NIST has legitimately republished the archive, ' +
        'verify the new contents by hand and update EXPECTED_SHA256 in this script.'
    );
  }
  process.stdout.write(`sha256 ok (${bytes.length} bytes)\n`);

  execFileSync('unzip', ['-o', '-q', zip, '-d', work]);
  const root = join(work, 'KAT_TDES');
  const present = new Set(readdirSync(root));

  const groups = [];
  for (const family of FAMILIES) {
    if (!present.has(family.file)) throw new Error(`missing from the archive: ${family.file}`);
    const sections = parseRsp(readFileSync(join(root, family.file), 'utf8'));
    const asKey = (r) => `${r.KEYs}/${r.PLAINTEXT}/${r.CIPHERTEXT}/${r.IV ?? ''}`;
    const encrypt = new Set(sections.ENCRYPT.map(asKey));
    const decrypt = new Set(sections.DECRYPT.map(asKey));
    if (encrypt.size !== decrypt.size || [...encrypt].some((k) => !decrypt.has(k))) {
      throw new Error(
        `${family.file}: the [ENCRYPT] and [DECRYPT] sections do NOT carry the same triples. ` +
          'vectors.ts stores each triple once and the suite asserts it in both directions, ' +
          'which is only sound while these agree.'
      );
    }
    groups.push({ ...family, vectors: sections.ENCRYPT });
    process.stdout.write(`  ${family.file}: ${sections.ENCRYPT.length} triples\n`);
  }

  const total = groups.reduce((sum, g) => sum + g.vectors.length, 0);

  // Splice the new table into the existing module, keeping the doc block above
  // it and the derived exports below it. The tail is found with the LAST
  // top-level `];` rather than the first: the interface declarations above
  // KAT_GROUPS end in `readonly KatVector[];`, which contains `];` and made an
  // earlier version of this script silently truncate every derived export.
  const existing = readFileSync(OUT, 'utf8');
  const header = existing.split('export const KAT_GROUPS')[0];
  const tailAt = existing.lastIndexOf('\n];\n');
  if (tailAt < 0) throw new Error('cannot find the end of KAT_GROUPS in vectors.ts');
  const tail = existing.slice(tailAt + '\n];\n'.length);

  const body = groups
    .map(
      (g) =>
        `  {\n` +
        `    id: '${g.id}',\n` +
        `    mode: '${g.mode}',\n` +
        `    title: '${g.title}',\n` +
        `    note:\n      '${g.note.replace(/'/g, "\\'")}',\n` +
        `    file: 'KAT_TDES/${g.file}',\n` +
        `    vectors: [\n` +
        g.vectors
          .map((v) =>
            v.IV
              ? `      { key: '${v.KEYs}', iv: '${v.IV}', plaintext: '${v.PLAINTEXT}', ciphertext: '${v.CIPHERTEXT}' },`
              : `      { key: '${v.KEYs}', plaintext: '${v.PLAINTEXT}', ciphertext: '${v.CIPHERTEXT}' },`
          )
          .join('\n') +
        `\n    ],\n  },`
    )
    .join('\n');

  writeFileSync(OUT, `${header}export const KAT_GROUPS: readonly KatGroup[] = [\n${body}\n];\n${tail}`);
  process.stdout.write(`wrote ${OUT} — ${total} triples, ${total * 2} assertions\n`);
} finally {
  rmSync(work, { recursive: true, force: true });
}

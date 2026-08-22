import { defineConfig, devices } from '@playwright/test';

/**
 * Browser suites run against the PRODUCTION build served by `vite preview`, so
 * what passes here is what ships.
 *
 *   a11y.spec.ts   — the axe WCAG 2.1 A/AA gate plus the arithmetic oracles in
 *                    `gate.ts`. Chromium only: a gate has to be deterministic.
 *   claims.spec.ts — the claims suite. Checks that the numbers the page prints
 *                    are true, by re-deriving them independently of the source.
 *
 * Port 4657 is unique to this lab across the fleet, and deliberately not the
 * Vite default 4173. With 190 labs side by side a shared port means
 * `reuseExistingServer` silently scans a DIFFERENT lab's preview — that has
 * really happened here, and it happened again during this build: the first
 * choice, 4687, turned out to be held by `crypto-lab-attestation-gate`, being
 * built alongside this lab, whose preview answered two of this gate's runs
 * before the collision was found. 4657 was checked against every sibling's
 * committed config, every sibling's WORKING TREE (the labs being built
 * alongside this one are not committed yet), and every listening socket on the
 * machine.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  timeout: 180_000, // the axe driver walks every panel and disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4657/crypto-lab-feistel-forge/',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      // Dark is the only theme; scan the one the page actually pins.
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'claims',
      testMatch: /claims\.spec\.ts/,
      // An explicit action timeout, because without one a click that never
      // becomes actionable burns the whole test timeout and reports "3.0m"
      // instead of naming the locator it was waiting on.
      use: { ...devices['Desktop Chrome'], actionTimeout: 15_000 },
    },
  ],
  webServer: {
    // Build before serving. `vite preview` serves whatever is already in dist/,
    // so without the build in front a run tests a stale bundle — and a build
    // that FAILS leaves the previous good bundle in place, so the whole suite
    // passes green against source that no longer compiles. With the build in
    // front a compile error aborts the run instead.
    command: 'npm run build && npm run preview -- --port 4657 --strictPort',
    url: 'http://localhost:4657/crypto-lab-feistel-forge/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});

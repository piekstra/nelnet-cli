#!/usr/bin/env node
// nlnt-capture.mjs — reference capture command for unattended nlnt re-login.
//
// Prints a fresh Nelnet session bundle (the browser's `oidc.user` JSON) to
// STDOUT so `nlnt auth refresh` (and automatic refresh) can renew without a
// human. Point nlnt at it once:
//
//   nlnt auth refresh --command "node /path/to/nlnt-capture.mjs" --save
//
// Two paths, cheapest first:
//   1. SILENT RENEWAL — reload the SPA in a persistent Chrome profile; while the
//      identity-provider session cookie is still valid, oidc-client mints a
//      fresh bundle with no password and no MFA. This is the common case.
//   2. FULL LOGIN — only when that cookie has lapsed: fill username/password and
//      read the one-time code from Gmail. Burns a real MFA code, so it is the
//      rare fallback.
//
// Why real Chrome (not Playwright's Chromium): Akamai's bot wall rejects
// Playwright's instrumented Chromium outright. This drives the genuine Google
// Chrome binary over CDP, which has a real fingerprint.
//
// Secrets: the portal password comes from the keychain (service `piekstra.nlnt`,
// account `password`) or $NLNT_PASSWORD — never argv. The bundle it prints IS a
// live credential; nlnt reads it from stdout and stores it in the keychain.
//
// Config via env:
//   NLNT_USERNAME            portal username (else read from `nlnt config`)
//   NLNT_PASSWORD            portal password (else keychain, see below)
//   NLNT_KEYCHAIN_SERVICE    keychain service for the password (default piekstra.nlnt)
//   NLNT_KEYCHAIN_ACCOUNT    keychain account for the password (default password)
//   NLNT_CAPTURE_PROFILE     Chrome user-data-dir (default ~/.cache/nlnt/chrome)
//   NLNT_CAPTURE_HEADED=1    show the window (for the first login / debugging)
//   NLNT_CHROME              path to Google Chrome binary
//   NLNT_PLAYWRIGHT_DIR      dir containing node_modules/playwright
//   NLNT_OTP_COMMAND         command that prints the 6-digit MFA code on stdout
//                            (this script does not read email; see mfa-via-mail)
//   NLNT_CAPTURE_PORT        CDP port (default 9455)

import { spawn, spawnSync, execSync } from 'node:child_process';
import { existsSync, readlinkSync, rmSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { homedir } from 'node:os';

const OIDC_KEY = 'oidc.user:https://auth.nelnet.studentaid.gov:mma';
const SPA = 'https://nelnet.studentaid.gov/dashboard';
const PORT = process.env.NLNT_CAPTURE_PORT || '9455';
const PROFILE = process.env.NLNT_CAPTURE_PROFILE || join(homedir(), '.cache/nlnt/chrome');
const HEADED = process.env.NLNT_CAPTURE_HEADED === '1';
const log = (...a) => console.error('[nlnt-capture]', ...a); // diagnostics → stderr

function chromePath() {
  if (process.env.NLNT_CHROME) return process.env.NLNT_CHROME;
  const mac = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  if (existsSync(mac)) return mac;
  for (const c of ['google-chrome', 'google-chrome-stable', 'chromium']) {
    // `which` is a real binary, so spawnSync runs it with NO shell — the
    // candidate name can never be shell-interpreted.
    const r = spawnSync('which', [c], { stdio: ['ignore', 'pipe', 'ignore'] });
    if (r.status === 0 && r.stdout.toString().trim()) return r.stdout.toString().trim();
  }
  throw new Error('Google Chrome not found — set $NLNT_CHROME to its path');
}

async function loadPlaywright() {
  const bases = [process.env.NLNT_PLAYWRIGHT_DIR, process.cwd()].filter(Boolean);
  const pick = (m) => (m?.chromium ? m : m?.default?.chromium ? m.default : null);
  for (const base of bases) {
    for (const entry of ['index.js', 'index.mjs']) {
      try {
        const m = pick(await import(pathToFileURL(join(base, 'node_modules/playwright', entry)).href));
        if (m) return m;
      } catch {
        /* next */
      }
    }
  }
  try {
    const m = pick(await import('playwright'));
    if (m) return m;
  } catch {
    /* fall through */
  }
  throw new Error('Playwright not found — `npm i playwright` and/or set $NLNT_PLAYWRIGHT_DIR');
}

function username() {
  if (process.env.NLNT_USERNAME) return process.env.NLNT_USERNAME;
  try {
    const cfg = JSON.parse(execSync('nlnt config show --json', { stdio: ['ignore', 'pipe', 'ignore'] }).toString());
    if (cfg.username) return cfg.username;
  } catch {
    /* ignore */
  }
  throw new Error('no username — set $NLNT_USERNAME or `nlnt config set username <you>`');
}

function password() {
  if (process.env.NLNT_PASSWORD) return process.env.NLNT_PASSWORD;
  const service = process.env.NLNT_KEYCHAIN_SERVICE || 'piekstra.nlnt';
  const account = process.env.NLNT_KEYCHAIN_ACCOUNT || 'password';
  // execFileSync (no shell) so the service/account values are never interpreted.
  const r = spawnSync('security', ['find-generic-password', '-s', service, '-a', account, '-w'], {
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  if (r.status === 0) return r.stdout.toString().replace(/\n$/, '');
  throw new Error(`no password — set $NLNT_PASSWORD or store it in keychain ${service}/${account}`);
}

// Get the 6-digit one-time code from `$NLNT_OTP_COMMAND` — a command that prints
// the code on stdout. This script deliberately does NOT read email itself:
// pulling an MFA code out of a mailbox is a cross-cutting concern that spans
// email and *any* CLI, so it belongs in a higher-level skill (`mfa-via-mail`),
// not baked into one provider's capture script. The script stays agnostic about
// where the code comes from; the caller supplies the code source.
async function fetchOtp() {
  const cmd = process.env.NLNT_OTP_COMMAND;
  if (!cmd) {
    throw new Error(
      'a full login needs an MFA code, but $NLNT_OTP_COMMAND is not set. Point it at a ' +
        'command that prints the 6-digit code (reading it from email is the mfa-via-mail ' +
        "skill's job). This script does not read mail itself.",
    );
  }
  for (let attempt = 0; attempt < 12; attempt++) {
    try {
      const text = execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
      const m = text.match(/\b(\d{6})\b/);
      if (m) return m[1];
    } catch (e) {
      log('otp command:', e.message);
    }
    await new Promise((r) => setTimeout(r, 5000)); // mail lands a few seconds late
  }
  throw new Error('$NLNT_OTP_COMMAND did not yield a 6-digit code after retries');
}

async function readBundle(page) {
  return page.evaluate((k) => localStorage.getItem(k), OIDC_KEY);
}

// A bundle is usable only if it has an access token that is NOT already
// expired. Silent renewal that fails leaves the OLD (expired) `oidc.user` in
// localStorage; emitting that would hand nlnt a dead token that 401s on the
// next call. Require the expiry to be comfortably in the future (60s skew).
function isFresh(raw) {
  try {
    const u = JSON.parse(raw);
    // Require a numeric expiry comfortably in the future. A bundle from
    // oidc-client always carries `expires_at`; demanding it (rather than
    // treating a missing one as fresh) keeps the staleness guard airtight.
    const now = Math.floor(Date.now() / 1000);
    return Boolean(u.access_token) && typeof u.expires_at === 'number' && u.expires_at > now + 60;
  } catch {
    return false;
  }
}

// Poll for oidc-client to (silently) populate a FRESH bundle. A stale one does
// not count — it means renewal did not actually happen.
async function waitForBundle(page, ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const raw = await readBundle(page).catch(() => null);
    if (raw && isFresh(raw)) return raw;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return null;
}

async function waitForLoginForm(page, ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await page.$('#username-textfield').then(Boolean).catch(() => false)) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

// Chrome leaves a SingletonLock symlink (`host-PID`) while running; a crash or
// kill strands it and the next launch silently fails to open the profile.
// Remove it only when its owning process is gone.
function cleanStaleLock(profile) {
  const lock = join(profile, 'SingletonLock');
  try {
    const pid = parseInt(readlinkSync(lock).split('-').pop(), 10);
    let alive = false;
    try {
      process.kill(pid, 0);
      alive = true;
    } catch {
      alive = false;
    }
    if (!alive) {
      for (const f of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
        try {
          rmSync(join(profile, f));
        } catch {
          /* already gone */
        }
      }
      log('removed a stale Chrome profile lock');
    }
  } catch {
    /* no lock, or not a symlink — nothing to clean */
  }
}

async function fullLogin(page) {
  log('identity session lapsed — performing full login');
  const type = async (selectors, value) => {
    for (const s of selectors) {
      const el = await page.$(s);
      if (el) {
        await el.fill(value);
        return true;
      }
    }
    return false;
  };
  const click = async (selectors) => {
    for (const s of selectors) {
      const el = await page.$(s);
      if (el) {
        await el.click().catch(() => {});
        return true;
      }
    }
    return false;
  };

  // The welcome page needs a click to reach the form; on a redirected login page
  // the field is already present, so these are best-effort.
  if (!(await page.$('#username-textfield'))) {
    await click(['#login-button', 'button:has-text("Log In")', 'a:has-text("Log In")']);
    await page.waitForTimeout(1500);
    await click(['#accept-disclaimer', 'button:has-text("Accept")']);
    await page.waitForTimeout(500);
  }

  if (!(await type(['#username-textfield', 'input[name="Username"]', 'input[autocomplete="username"]'], username()))) {
    throw new Error('username field not found — the login DOM changed; run with NLNT_CAPTURE_HEADED=1 to inspect');
  }
  await type(['#password-textfield', 'input[type="password"]', 'input[name="Password"]'], password());
  // "Keep me signed in" extends the identity session (longer silent-renewal window).
  await page.$('#rememberLogin').then((el) => el?.check({ force: true }).catch(() => {}));
  await click(['#btnSubmit', 'button:has-text("Continue")', 'button[type="submit"]']);
  await page.waitForTimeout(3500);

  // A trusted device skips MFA entirely — only run the code flow if a challenge
  // actually appears (an auth-choice radio or a code field).
  const needsCode = await page
    .$('#code-textfield, [id^="mfa-option"], input[name="AuthChoice"]')
    .then(Boolean)
    .catch(() => false);
  if (!needsCode) {
    log('no MFA challenge — trusted device, proceeding');
    return;
  }

  // On the channel-choice page, prefer email (the only channel a mail-reading
  // OTP command can automate) and request the code.
  if (await page.$('input[name="AuthChoice"]')) {
    await page.$('#mfa-option-1').then((el) => el?.check({ force: true }).catch(() => {}));
    await click(['button:has-text("Send Code")', 'button:has-text("Email")']);
    await page.waitForTimeout(2500);
  }

  const code = await fetchOtp();
  log('got one-time code');
  await type(['#code-textfield', 'input[name="UserCode"]', 'input[autocomplete="one-time-code"]'], code);
  // Remember this device so future re-logins skip MFA.
  await page.$('#trustedDevice').then((el) => el?.check({ force: true }).catch(() => {}));
  await click(['#btnSubmit', 'button:has-text("Verify")', 'button[type="submit"]']);
  await page.waitForTimeout(4000);
}

async function main() {
  const { chromium } = await loadPlaywright();
  const chrome = chromePath();
  cleanStaleLock(PROFILE);
  log(`launching ${HEADED ? 'headed' : 'headless'} Chrome (${chrome})`);
  const args = [
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${PROFILE}`,
    '--no-first-run',
    '--no-default-browser-check',
  ];
  if (!HEADED) args.push('--headless=new');
  const proc = spawn(chrome, args, { stdio: 'ignore', detached: false });

  let browser;
  try {
    // Wait for the CDP endpoint.
    for (let i = 0; i < 40 && !browser; i++) {
      try {
        browser = await chromium.connectOverCDP(`http://127.0.0.1:${PORT}`);
      } catch {
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    if (!browser) throw new Error('Chrome did not expose a CDP endpoint');

    const ctx = browser.contexts()[0];
    const page = ctx.pages()[0] || (await ctx.newPage());
    await page.goto(SPA, { waitUntil: 'domcontentloaded' }).catch(() => {});

    // Path 1: silent renewal — a FRESH bundle while the identity session lives.
    let raw = await waitForBundle(page, 12000);

    // Path 2: the identity session has lapsed (no fresh bundle). Clear the stale
    // session so the SPA starts a real sign-in, then drive the full login.
    if (!raw) {
      log('no fresh session from silent renewal — the identity session has lapsed');
      await ctx.clearCookies().catch(() => {});
      await page.evaluate(() => {
        localStorage.clear();
        sessionStorage.clear();
      }).catch(() => {});
      await page.goto(SPA, { waitUntil: 'domcontentloaded' }).catch(() => {});
      if (await waitForLoginForm(page, 20000)) {
        await fullLogin(page);
        await page.goto(SPA, { waitUntil: 'domcontentloaded' }).catch(() => {});
        raw = await waitForBundle(page, 15000);
      }
    }

    // Never emit a stale token: fail loudly with an actionable message instead.
    if (!raw) {
      throw new Error(
        'could not obtain a fresh session — the identity session lapsed and a full login did ' +
          'not complete (it needs username/password and, unless this device is trusted, an MFA ' +
          'code via $NLNT_OTP_COMMAND). Run `nlnt auth login --browser --overwrite`, or set ' +
          'NLNT_CAPTURE_HEADED=1 to watch the flow.',
      );
    }
    process.stdout.write(raw.trim() + '\n'); // the ONLY thing on stdout — guaranteed fresh
  } finally {
    try {
      await browser?.close();
    } catch {
      /* ignore */
    }
    try {
      proc.kill('SIGTERM');
    } catch {
      /* ignore */
    }
  }
}

main().catch((e) => {
  log('ERROR:', e.message);
  process.exit(1);
});

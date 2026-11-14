'use strict';
const { chromium } = require('playwright');
const { readFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const path = require('node:path');

const directory = process.env.RAG_LAB_PATH;
const origin = 'http://localhost:8000';
const accounts = JSON.parse(readFileSync(path.join(directory, 'keycloak/accounts.json')));
const compose = (...args) => {
  const result = spawnSync('docker', ['compose', '--env-file', path.join(directory, 'compose.env'), '-p', 'juniper-reference', '-f', 'compose.production.yml', '-f', 'compose.reference.yml', ...args], {stdio: 'inherit'});
  assert.equal(result.status, 0, `compose command failed: ${args[0]}`);
};
const admin = (...args) => compose('run', '--rm', '--no-deps', 'api', 'python', 'production_admin.py', ...args);
const publish = release => {
  assert.equal(spawnSync('python3', ['reference/corpus.py', path.join(directory, 'source'), String(release)], {stdio:'inherit'}).status, 0);
  admin('sync-source', '/lab/source');
};
const signIn = async (page, user, hash = '') => {
  await page.goto(`${origin}/reference/${hash}`);
  await page.getByRole('button', {name:'Sign in'}).click();
  await page.locator('#username').fill(user);
  await page.locator('#password').fill(accounts[user].password);
  await page.locator('#kc-login').click();
};
const search = async page => {
  await page.locator('#question').fill('Which expenses need manager approval?');
  await page.getByRole('button', {name:'Search',exact:true}).click();
};

(async () => {
  const browser = await chromium.launch({headless:true, ...(process.env.RAG_BROWSER_EXECUTABLE ? {executablePath:process.env.RAG_BROWSER_EXECUTABLE} : {})});
  try {
    // The lab uses a disposable local certificate. curl checks its exact CA separately.
    const context = await browser.newContext({ignoreHTTPSErrors:true});
    const page = await context.newPage();
    await signIn(page, 'avery');
    await page.getByText('Signed in.', {exact:true}).waitFor();
    await search(page);
    await page.getByText(/exceeds 250 credits/).first().waitFor();
    await page.getByRole('link', {name:'Open verified passage'}).first().click();
    await page.getByText('Current authorised passage.', {exact:true}).waitFor();
    const oldLink = new URL(page.url()).hash;
    publish(2);
    await search(page);
    await page.getByText(/exceeds 150 credits/).first().waitFor();
    await page.getByRole('link', {name:'Open verified passage'}).first().click();
    await page.getByText('Current authorised passage.', {exact:true}).waitFor();
    const currentLink = new URL(page.url()).hash;
    assert.notEqual(oldLink,currentLink);
    await page.evaluate(hash => { location.hash = hash; }, oldLink);
    await page.getByText('This passage is unavailable.', {exact:true}).waitFor();
    await page.evaluate(hash => { location.hash = hash; }, currentLink);
    await page.getByText('Current authorised passage.', {exact:true}).waitFor();
    admin('backup','/var/lib/rag/lab-backup.sqlite3');
    admin('revoke',accounts.avery.sub);
    await page.evaluate(hash => { location.hash = hash; }, oldLink);
    await page.getByText('Access is no longer available.', {exact:true}).waitFor();
    await signIn(page, 'robin', currentLink);
    await page.getByText('This passage is unavailable.', {exact:true}).waitFor();
    publish(3);
    compose('stop','api');
    admin('--database','/var/lib/rag/lab-backup.sqlite3','quarantine-restored-grants');
    // Reconcile withdrawals before activating an older snapshot.
    admin('--database','/var/lib/rag/lab-backup.sqlite3','sync-source','/lab/source');
    admin('activate-restore','/var/lib/rag/lab-backup.sqlite3');
    compose('up','-d','api');
    await new Promise(resolve => setTimeout(resolve,2500));
    await signIn(page,'avery',currentLink);
    await page.getByText('Access is no longer available.',{exact:true}).waitFor();
    admin('grant',accounts.avery.sub,'analyst');
    await new Promise(resolve => setTimeout(resolve,1600));
    await signIn(page,'avery',currentLink);
    await page.getByText('This passage is unavailable.',{exact:true}).waitFor();
    console.log('PASS: Keycloak sign-in, document update, live links, denial, withdrawal and reconciled restore.');
  } finally { await browser.close(); }
})().catch(err=>{ console.error(err.message);process.exitCode=1; });

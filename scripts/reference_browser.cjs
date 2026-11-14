'use strict';
const { chromium } = require('playwright');
const { readFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const { X509Certificate } = require('node:crypto');
const path = require('node:path');

const directory = process.env.RAG_LAB_PATH;
const origin = 'http://localhost:8000';
const trust = readFileSync(path.join(directory, 'cert.pem'));
const expectedCertificate = new X509Certificate(trust).fingerprint256;
assert.match(expectedCertificate,/^[0-9A-F:]+$/);
const accounts = JSON.parse(readFileSync(path.join(directory, 'keycloak/accounts.json')));
const prefix = ['compose', '--env-file', path.join(directory, 'compose.env'), '-p', 'juniper-reference', '-f', 'compose.production.yml', '-f', 'compose.reference.yml'];
function docker(args, capture = false) {
  const result = spawnSync('docker', [...prefix, ...args], {stdio: capture ? ['ignore','pipe','inherit'] : 'inherit', encoding:'utf8',timeout:90000});
  assert.equal(result.status, 0, `compose command failed: ${args[0]}`);
  return result.stdout;
}
const compose = (...args) => docker(args);
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
const operator = (...args) => compose('exec','-T','idp','/opt/keycloak/bin/kcadm.sh',...args);
const activeSigningKey = () => JSON.parse(docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','get','keys','-r','juniper'],true)).active.RS256;
const operatorLogin = () => compose('exec','-T','idp','sh','-ec',
  '/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user lab-operator --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"');
async function waitForStatus(route, expected, timeoutMs = 30_000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try { if ((await fetch(`${origin}${route}`, {signal: AbortSignal.timeout(6000)})).status === expected) return; }
    catch { /* brief restart */ }
    await new Promise(resolve => setTimeout(resolve,500));
  }
  throw Error(`Timed out waiting for ${route} to return ${expected}.`);
}
const search = async page => {
  await page.locator('#question').fill('Which expense needs manager approval?');
  await page.getByRole('button', {name:'Search',exact:true}).click();
};

(async () => {
  const browser = await chromium.launch({headless:true, ...(process.env.RAG_BROWSER_EXECUTABLE ? {executablePath:process.env.RAG_BROWSER_EXECUTABLE} : {})});
  try {
    // The lab uses a disposable local certificate. curl checks its exact CA separately.
    const context = await browser.newContext({ignoreHTTPSErrors:true});
    const page = await context.newPage();
    page.setDefaultTimeout(20000);
    await signIn(page, 'avery');
    await page.getByText('Signed in.', {exact:true}).waitFor();
    await search(page);
    await page.getByText(/exceeds 250 credits/).first().waitFor();
    if (process.env.RAG_LAB_TEST_MODEL === '1') {
      await page.locator('#synth').check();
      await search(page);
      await page.getByText('Local model selected these source quotes.',{exact:true}).waitFor();
      await page.getByText(/exceeds 250 credits/).first().waitFor();
      await page.locator('#synth').uncheck();
    }
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
    operatorLogin();
    const oldKid = activeSigningKey();
    assert.equal(typeof oldKid,'string');
    const realm = JSON.parse(docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','get','realms/juniper'],true));
    operator('create','components','-r','juniper','-s',`parentId=${realm.id}`,'-s','name=lab-rollover',
      '-s','providerId=rsa-generated','-s','providerType=org.keycloak.keys.KeyProvider',
      '-s','config.priority=["200"]','-s','config.algorithm=["RS256"]','-s','config.keySize=["2048"]');
    assert.notEqual(activeSigningKey(),oldKid);
    // Fresh verifier process guarantees the old cached key set cannot mask rollover.
    compose('up','-d','--no-deps','--force-recreate','api');
    await waitForStatus('/ready',200,90000);
    await signIn(page,'avery');
    await page.getByText('Signed in.',{exact:true}).waitFor();
    await page.locator('#question').fill('Which day are office supply orders consolidated?');
    await page.getByRole('button',{name:'Search',exact:true}).click();
    await page.getByText(/consolidated every Tuesday/).first().waitFor();
    console.log('PASS: freshly rotated Keycloak signing key works with a cold verifier.');
    operator('update',`users/${accounts.avery.sub}`,'-r','juniper','-s','attributes.rag_role=["auditor"]');
    await signIn(page,'avery',currentLink);
    await page.getByText('Access is no longer available.',{exact:true}).waitFor();
    operator('update',`users/${accounts.avery.sub}`,'-r','juniper','-s','enabled=false');
    await signIn(page,'avery');
    await page.locator('#input-error').waitFor();
    console.log('PASS: fresh role mismatch denied and disabled account cannot sign in.');
    // Restart the API during the outage to remove cached signing keys.
    compose('stop','idp');
    compose('up','-d','--no-deps','--force-recreate','api');
    await waitForStatus('/health',200);
    await waitForStatus('/ready',503);
    compose('up','-d','idp');
    await waitForStatus('/ready',200,90_000);
    console.log('PASS: readiness fails closed during uncached IdP outage and recovers.');
  } finally { await browser.close(); }
})().catch(err=>{ console.error(err.message);process.exitCode=1; });

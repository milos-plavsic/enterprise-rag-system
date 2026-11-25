'use strict';
const { chromium } = require('playwright');
const { readFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const https = require('node:https');
const assert = require('node:assert/strict');
const path = require('node:path');

const directory = process.env.RAG_LAB_PATH;
const origin = 'http://localhost:8000';
const idpOrigin = 'https://localhost:8443';
const idpRealm = '/realms/juniper';
const accounts = JSON.parse(readFileSync(path.join(directory, 'keycloak/accounts.json')));
const probe = JSON.parse(readFileSync(path.join(directory, 'keycloak/probe.json')));
const labCa = readFileSync(path.join(directory,'cert.pem'));
const prefix = ['compose', '--env-file', path.join(directory, 'compose.env'), '-p', 'juniper-reference', '-f', 'compose.production.yml', '-f', 'compose.reference.yml'];
function docker(args, capture = false, input) {
  const result = spawnSync('docker', [...prefix, ...args], {stdio: [input === undefined ? 'ignore' : 'pipe',capture ? 'pipe' : 'inherit','inherit'], input, encoding:'utf8',timeout:90000});
  assert.equal(result.status, 0, `compose command failed: ${args[0]}`);
  return result.stdout;
}
const compose = (...args) => docker(args);
const admin = (...args) => compose('run', '--rm', '--no-deps', 'api', 'python', 'production_admin.py', ...args);
const publish = release => {
  assert.equal(spawnSync('python3', ['reference/corpus.py', path.join(directory, 'source'), String(release)], {stdio:'inherit'}).status, 0);
  admin('sync-source', '/lab/source');
};
const isIdpAuth = url => url.origin === idpOrigin &&
  url.pathname === idpRealm + '/protocol/openid-connect/auth';
const isCredentialPost = response => response.request().method() === 'POST' &&
  new URL(response.url()).origin === idpOrigin &&
  new URL(response.url()).pathname.includes('/login-actions/authenticate');
const isTokenPost = response => response.request().method() === 'POST' &&
  new URL(response.url()).origin === idpOrigin &&
  new URL(response.url()).pathname === idpRealm + '/protocol/openid-connect/token';
const signIn = async (page, user, hash = '', expectCallback = true) => {
  await page.goto(`${origin}/reference/${hash}`,
    {waitUntil:'domcontentloaded',timeout:45000});
  await page.getByRole('button',{name:'Sign in'}).click();
  // The visible Keycloak credential form is the stable navigation condition.
  // Chromium can emit ERR_NETWORK_CHANGED during Docker network transitions even
  // when the destination loaded successfully, so do not couple correctness to a
  // navigation event. Verify the actual loaded URL after the form is present.
  await page.locator('#username').waitFor({state:'visible',timeout:45000});
  assert.ok(isIdpAuth(new URL(page.url())),`unexpected identity-provider URL ${page.url()}`);
  await page.locator('#username').fill(user);
  await page.locator('#password').fill(accounts[user].password);
  const submitted = page.waitForResponse(isCredentialPost,{timeout:45000});
  // A successful token exchange is the authoritative proof that the OAuth
  // callback loaded and executed. A concurrent waitForURL is redundant and can
  // fail with Chromium ERR_NETWORK_CHANGED while Docker recreates lab networks.
  const exchanged = expectCallback ? page.waitForResponse(isTokenPost,{timeout:45000}) : null;
  await page.locator('#kc-login').click();
  const credentialResponse = await submitted;
  let accessToken;
  if (exchanged) {
    const tokenResponse = await exchanged;
    assert.equal(tokenResponse.status(),200,
      `token endpoint returned ${tokenResponse.status()}`);
    const payload = await tokenResponse.json();
    assert.equal(typeof payload.access_token,'string','token response missing access token');
    accessToken = payload.access_token;
    // A callback carrying a citation hash immediately replaces the status
    // with the citation result; only no-hash logins have a stable Signed in state.
    if (!hash) await page.getByText('Signed in.',{exact:true}).waitFor({timeout:15000});
  }
  return {credentialResponse,accessToken};
};
const citationUrl = hash => origin + hash.slice(1);
async function expectCitationAfterSignIn(page, user, hash, expectedStatus, message) {
  assert.ok(hash.startsWith('#/v1/documents/'), `unexpected citation hash ${hash}`);
  const {accessToken} = await signIn(page,user,hash);
  assert.equal(typeof accessToken,'string','callback did not yield an access token');
  // The deep-link UI assertion below proves the browser callback followed the
  // requested citation. Verify the authorization status independently so a
  // Playwright network-event race cannot hide or fabricate a 403/404 result.
  const verification = await fetch(citationUrl(hash), {
    headers:{Authorization:`Bearer ${accessToken}`},
    redirect:'error',
    signal:AbortSignal.timeout(15000),
  });
  assert.equal(verification.status,expectedStatus,
    `citation ${hash} returned ${verification.status}, expected ${expectedStatus}`);
  await verification.arrayBuffer();
  await page.getByText(message,{exact:true}).waitFor({timeout:15000});
}
async function expectCitationHash(page, hash, expectedStatus, message) {
  assert.ok(hash.startsWith('#/v1/documents/'), `unexpected citation hash ${hash}`);
  const response = page.waitForResponse(r =>
    r.request().method() === 'GET' && r.url() === citationUrl(hash),
    {timeout: 45000});
  await page.evaluate(next => { location.hash = next; }, hash);
  const result = await response;
  assert.equal(result.status(),expectedStatus,
    `citation ${hash} returned ${result.status()}, expected ${expectedStatus}`);
  await page.getByText(message,{exact:true}).waitFor({timeout:15000});
}
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
// Admin key activation is not proof that the public JWKS endpoint has converged.
async function waitForPublishedSigningKey(kid, timeoutMs = 30000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const result = spawnSync('curl', ['--silent','--fail','--max-time','4','--cacert',
      path.join(directory,'cert.pem'),
      'https://localhost:8443/realms/juniper/protocol/openid-connect/certs'],
      {encoding:'utf8',timeout:5000});
    if (result.status === 0) {
      const jwks = JSON.parse(result.stdout);
      if (jwks.keys.some(key => key.kid === kid && key.kty === 'RSA' && key.use === 'sig')) return;
    }
    await new Promise(resolve => setTimeout(resolve,500));
  }
  throw Error('Rotated signing key was not published in the trusted JWKS within 30 seconds.');
}

function probeToken() {
  return new Promise((resolve,reject) => {
    const body = 'grant_type=client_credentials';
    const authorization = 'Basic ' + Buffer.from(
      `${probe.client_id}:${probe.client_secret}`,'utf8').toString('base64');
    const request = https.request({
      hostname:'localhost',port:8443,path:idpRealm + '/protocol/openid-connect/token',
      method:'POST',ca:labCa,rejectUnauthorized:true,timeout:4000,
      headers:{Authorization:authorization,'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':Buffer.byteLength(body)},
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 65536) {
          request.destroy(Error('probe token response exceeds 64 KiB'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve({
        status:response.statusCode,
        body:Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.on('timeout',() => request.destroy(Error('probe token request timed out')));
    request.on('error',reject);
    request.end(body);
  });
}
async function waitForIssuedSigningKey(kid, timeoutMs = 30000) {
  const until = Date.now() + timeoutMs;
  let lastStatus = 'no response';
  while (Date.now() < until) {
    try {
      const result = await probeToken();
      lastStatus = result.status;
      if (result.status === 200) {
        const token = JSON.parse(result.body).access_token;
        if (typeof token === 'string') {
          const parts = token.split('.');
          if (parts.length === 3) {
            const header = JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8'));
            if (header.kid === kid && header.alg === 'RS256') return;
          }
        }
      }
    } catch (error) {
      lastStatus = error.name;
    }
    await new Promise(resolve => setTimeout(resolve,500));
  }
  throw Error(`Rotated signing key did not issue a probe token within 30 seconds (last status: ${lastStatus}).`);
}
async function expectRotatedSignIn(page) {
  try {
    await signIn(page,'avery');
  } catch (error) {
    const failed = await page.getByText(
      'Sign-in could not be verified. Start again.',{exact:true}).isVisible();
    throw Error(
      `Post-rollover sign-in failed (callback failure: ${failed}; phase: ${page.url().startsWith(idpOrigin) ? 'identity-provider' : 'application'}).`,
      {cause:error});
  }
}
const search = async page => {
  await page.locator('#question').fill('Which expense needs manager approval?');
  await page.getByRole('button', {name:'Search',exact:true}).click();
};

async function waitForBrowserNetwork(context, timeoutMs = 30000) {
  const discovery = idpOrigin + idpRealm + '/.well-known/openid-configuration';
  const until = Date.now() + timeoutMs;
  let consecutive = 0;
  while (Date.now() < until) {
    const probePage = await context.newPage();
    try {
      const response = await probePage.goto(discovery,{waitUntil:'domcontentloaded',timeout:5000});
      consecutive = response && response.status() === 200 ? consecutive + 1 : 0;
    } catch (error) {
      // Docker network transitions can briefly surface Chromium ERR_NETWORK_CHANGED.
      // This is an environment readiness probe; the authentication flow itself is
      // never retried or accepted after a failed attempt.
      consecutive = 0;
    } finally {
      await probePage.close();
    }
    if (consecutive >= 2) return;
    await new Promise(resolve => setTimeout(resolve,300));
  }
  throw Error('Chromium could not establish a stable connection to the reference IdP.');
}

(async () => {
  const browser = await chromium.launch({headless:true, ...(process.env.RAG_BROWSER_EXECUTABLE ? {executablePath:process.env.RAG_BROWSER_EXECUTABLE} : {})});
  try {
    // The lab uses a disposable local certificate. curl checks its exact CA separately.
    const fresh = async () => {
      const context = await browser.newContext({ignoreHTTPSErrors:true});
      await waitForBrowserNetwork(context);
      const page = await context.newPage();
      page.setDefaultTimeout(30000);
      page.setDefaultNavigationTimeout(45000);
      return page;
    };
    let page = await fresh();
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
    await expectCitationHash(page,oldLink,403,'Access is no longer available.');
    page = await fresh();
    await expectCitationAfterSignIn(page,'robin',currentLink,404,'This passage is unavailable.');
    publish(3);
    compose('stop','api');
    admin('--database','/var/lib/rag/lab-backup.sqlite3','quarantine-restored-grants');
    // Reconcile withdrawals before activating an older snapshot.
    admin('--database','/var/lib/rag/lab-backup.sqlite3','sync-source','/lab/source');
    admin('activate-restore','/var/lib/rag/lab-backup.sqlite3');
    compose('up','-d','api');
    await waitForStatus('/ready',200,90000);
    page = await fresh();
    await expectCitationAfterSignIn(page,'avery',currentLink,403,'Access is no longer available.');
    admin('grant',accounts.avery.sub,'analyst');
    await new Promise(resolve => setTimeout(resolve,6500));
    page = await fresh();
    await expectCitationAfterSignIn(page,'avery',currentLink,404,'This passage is unavailable.');
    console.log('PASS: Keycloak sign-in, document update, live links, denial, withdrawal and reconciled restore.');
    operatorLogin();
    const oldKid = activeSigningKey();
    assert.equal(typeof oldKid,'string');
    const realm = JSON.parse(docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','get','realms/juniper'],true));
    operator('create','components','-r','juniper','-s',`parentId=${realm.id}`,'-s','name=lab-rollover',
      '-s','providerId=rsa-generated','-s','providerType=org.keycloak.keys.KeyProvider',
      '-s','config.priority=["200"]','-s','config.algorithm=["RS256"]','-s','config.keySize=["2048"]');
    const newKid = activeSigningKey();
    assert.equal(typeof newKid,'string');
    assert.notEqual(newKid,oldKid);
    await waitForPublishedSigningKey(newKid);
    await waitForIssuedSigningKey(newKid);
    // Fresh verifier process guarantees the old cached key set cannot mask rollover.
    compose('up','-d','--no-deps','--force-recreate','api');
    await waitForStatus('/ready',200,90000);
    page = await fresh();
    await expectRotatedSignIn(page);
    await page.locator('#question').fill('Which day are office supply orders consolidated?');
    await page.getByRole('button',{name:'Search',exact:true}).click();
    await page.getByText(/consolidated every Tuesday/).first().waitFor();
    console.log('PASS: freshly rotated Keycloak signing key works with a cold verifier.');
    const profilePath = 'users/profile';
    const profile = JSON.parse(docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','get',profilePath,'-r','juniper'],true));
    // Manage this claim explicitly. Never allow the end user to set their own role.
    profile.attributes.push({name:'rag_role',displayName:'RAG role',multivalued:false,
      permissions:{view:['admin'],edit:['admin']},validations:{options:{options:['analyst','manager','auditor']}}});
    docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','update',profilePath,'-r','juniper','-n','-f','-'],false,JSON.stringify(profile));
    const userPath = `users/${accounts.avery.sub}`;
    const user = () => JSON.parse(docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','get',userPath,'-r','juniper'],true));
    const identity = user();
    identity.attributes = {...identity.attributes,rag_role:['auditor']};
    docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','update',userPath,'-r','juniper','-n','-f','-'],false,JSON.stringify(identity));
    assert.deepEqual(user().attributes.rag_role,['auditor']);
    page = await fresh();
    await expectCitationAfterSignIn(page,'avery',currentLink,403,'Access is no longer available.');
    const disabled = {...user(),enabled:false};
    docker(['exec','-T','idp','/opt/keycloak/bin/kcadm.sh','update',userPath,'-r','juniper','-n','-f','-'],false,JSON.stringify(disabled));
    assert.equal(user().enabled,false);
    page = await fresh();
    const {credentialResponse: refusal} = await signIn(page,'avery','',false);
    assert.ok(refusal.status() === 200 || refusal.status() === 400 || refusal.status() === 403,
      `unexpected disabled-login status ${refusal.status()}`);
    await page.waitForURL(url => url.origin === 'https://localhost:8443' && url.pathname.includes('/login-actions/'));
    await page.getByText(/invalid username or password|account is disabled|account disabled|invalid credentials/i).first().waitFor();
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

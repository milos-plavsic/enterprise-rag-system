'use strict';
const issuer = 'https://localhost:8443/realms/juniper';
const clientId = 'juniper-browser';
const redirect = `${location.origin}/reference/`;
const requestedLink = () => location.hash;
const $ = id => document.getElementById(id);
let token, expiration = 0, sessionGeneration = 0;
const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const nonce = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
const say = message => { $('status').textContent = message; };
const clear = () => {
  ++sessionGeneration;
  token = undefined;
  expiration = 0;
  $('results').replaceChildren();
  $('search').hidden = $('signout').hidden = true;
  $('signin').hidden = false;
};
async function login() {
  const verifier = nonce(), state = nonce();
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  sessionStorage.setItem('juniper.pkce', JSON.stringify({verifier, state, at: Date.now(), hash: requestedLink()}));
  location.assign(`${issuer}/protocol/openid-connect/auth?${new URLSearchParams({client_id: clientId, response_type: 'code', scope: 'openid', redirect_uri: redirect, state, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'login'})}`);
}
async function callback() {
  const params = new URLSearchParams(location.search);
  if (!params.has('code') && !params.has('error')) return;
  history.replaceState(null, '', location.pathname + location.hash);
  const pending = JSON.parse(sessionStorage.getItem('juniper.pkce') || 'null');
  sessionStorage.removeItem('juniper.pkce');
  if (!pending || Date.now() - pending.at > 300_000 || pending.state !== params.get('state') || params.get('iss') !== issuer || !params.get('code')) throw Error();
  const r = await fetch(`${issuer}/protocol/openid-connect/token`, {method: 'POST', credentials: 'omit', redirect: 'error', body: new URLSearchParams({grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirect, code: params.get('code'), code_verifier: pending.verifier})});
  if (!r.ok) throw Error();
  const result = await r.json();
  if (typeof result.access_token !== 'string' || !Number.isFinite(result.expires_in) || result.expires_in <= 0) throw Error();
  token = result.access_token;
  expiration = Date.now() + result.expires_in * 1000;
  const session = ++sessionGeneration;
  setTimeout(() => { if (sessionGeneration === session) { clear(); say('Session expired. Sign in again.'); } }, result.expires_in * 1000);
  $('search').hidden = $('signout').hidden = false;
  $('signin').hidden = true;
  say('Signed in.');
  if (pending.hash && linkPattern.test(pending.hash.slice(1))) {
    history.replaceState(null, '', location.pathname + pending.hash);
    await openCitation();
  }
}
async function api(path, opts = {}) {
  if (!token || Date.now() >= expiration) { clear(); throw Error('Sign in again.'); }
  const response = await fetch(path, {...opts, redirect: 'error', cache: 'no-store', headers: {...opts.headers, Authorization: `Bearer ${token}`}});
  if (response.status === 401 || response.status === 403) { clear(); throw Error('Access is no longer available.'); }
  if (!response.ok) throw Error(response.status === 404 ? 'This passage is unavailable.' : 'The service is temporarily unavailable.');
  return response.json();
}
const linkPattern = /^\/v1\/documents\/[a-f0-9]{32}\/passages\/[1-9]\d{0,1}\/[1-9]\d{0,3}$/;
function article(row) {
  const item = document.createElement('article');
  const title = document.createElement('h2'); title.textContent = row.title || 'Document passage';
  const body = document.createElement('pre'); body.textContent = row.text;
  const label = document.createElement('p'); label.textContent = `Page ${row.page}${row.version ? ` · version ${row.version}` : ''}`;
  item.append(title, label, body);
  if (linkPattern.test(row.href)) {
    const link = document.createElement('a'); link.href = '#' + row.href; link.textContent = 'Open verified passage'; item.append(link);
  }
  return item;
}
let navigation = 0;
async function openCitation() {
  const path = location.hash.slice(1);
  if (!linkPattern.test(path) || !token) return;
  const current = ++navigation, session = sessionGeneration;
  $('results').replaceChildren();
  try { const row = await api(path); if (session === sessionGeneration && current === navigation) { $('results').append(article(row)); say('Current authorised passage.'); } }
  catch (e) { if (current === navigation) say(e.message); }
}
$('signin').addEventListener('click', () => login().catch(() => say('Sign-in could not start.')));
$('signout').addEventListener('click', () => { clear(); say('This page’s session was cleared.'); });
window.addEventListener('hashchange', openCitation);
$('search').addEventListener('submit', async event => {
  event.preventDefault();
  const current = ++navigation, session = sessionGeneration;
  history.replaceState(null, '', location.pathname);
  $('results').replaceChildren(); say('Searching…');
  try {
    const result = await api('/v1/query', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({query: $('question').value, answer: $('synth').checked})});
    if (session !== sessionGeneration || current !== navigation) return;
    say(result.status === 'selected_quotes' ? 'Local model selected these source quotes.' : result.answer);
    for (const selected of result.excerpts || []) $('results').append(article({...selected.citation, text: selected.quote}));
    if (!result.excerpts) for (const row of result.evidence) $('results').append(article(row));
  } catch (e) { if (current === navigation) say(e.message); }
});
callback().catch(() => { clear(); say('Sign-in could not be verified. Start again.'); });

const $ = (id) => document.getElementById(id);
const icon = (name) => `<svg aria-hidden="true"><use href="/static/icons.svg#${name}"/></svg>`;

const state = {
  username: document.documentElement.dataset.user || '',
  vault: null,
  // The AES key lives only here, so a reload or Lock asks for the passcode again.
  key: null,
  // { id, encrypted: { id, nonce, ciphertext }, code: { issuer, name, secret, digits, algorithm, period } | null }
  codes: [],
  query: '',
  fresh: null,
  menuFor: null,
};

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function api(path, options = {}) {
  let res;
  try {
    res = await fetch(path, { credentials: 'same-origin', ...options });
  } catch {
    throw new ApiError(navigator.onLine ? "Couldn't reach roturAuth. Try again in a moment." : "You're offline. Reconnect and try again.", 0);
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(data?.error || `Something went wrong on our side (${res.status}). Try again.`, res.status);
  return data;
}

function postJSON(path, body) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

function show(screen) {
  for (const id of ['screen-loading', 'screen-error', 'screen-passcode', 'screen-codes']) $(id).hidden = id !== screen;
}

/* ---------- Crypto ---------- */

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (text) => new Uint8Array(text.match(/../g).map((h) => parseInt(h, 16)));

// The vault's format: PBKDF2-SHA-256 of the passcode is the AES-GCM key, and the SHA-256 of
// that key is stored as the verifier, so a wrong passcode is caught before decrypting.
async function deriveKey(passcode, saltHex, iterations) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passcode), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unhex(saltHex), iterations, hash: 'SHA-256' }, base, 256));
  const verifier = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bits)));
  const key = await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  bits.fill(0);
  return { key, verifier };
}

async function encrypt(id, code) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(code));
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, state.key, data);
  return { id, nonce: hex(nonce), ciphertext: hex(new Uint8Array(sealed)) };
}

async function decrypt(entry) {
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unhex(entry.nonce) }, state.key, unhex(entry.ciphertext));
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    return null;
  }
}

/* ---------- Opening ---------- */

async function open() {
  show('screen-loading');
  try {
    state.vault = await api('/api/vault');
    if (state.vault.username) state.username = state.vault.username;
    startPasscode(state.vault.setup ? 'unlock' : 'choose');
  } catch (error) {
    showOpenError(error);
  }
}

function showOpenError(error) {
  const refused = error.status === 401;
  const offline = error.status === 0 && !navigator.onLine;
  $('error-icon').setAttribute('href', `/static/icons.svg#${offline ? 'wifi-off' : 'circle-alert'}`);
  $('error-title').textContent = refused ? 'Sign in again' : "Couldn't open your codes";
  $('error-text').textContent = refused
    ? `${error.message.replace(/ Sign in again.*$/, '')} Your codes are safe in your Rotur files.`
    : `${error.message} Your codes are safe in your Rotur files.`;
  $('error-action').textContent = refused ? 'Sign in again' : 'Try again';
  $('error-action').onclick = refused ? signOut : open;
  show('screen-error');
  $('error-action').focus();
}

/* ---------- Passcode ---------- */

const passcode = { mode: 'unlock', digits: '', first: '', busy: false };

const passcodeCopy = {
  choose: { title: 'Choose a passcode', hint: 'Six digits. Your codes are encrypted with it before they’re saved, so it can’t be reset. Pick one you’ll remember.' },
  confirm: { title: 'Enter it again', hint: 'To be sure it’s the one you meant.' },
  unlock: { title: 'Enter your passcode', hint: '' },
};

function startPasscode(mode, message = '') {
  passcode.mode = mode;
  passcode.digits = '';
  $('passcode-title').textContent = passcodeCopy[mode].title;
  $('passcode-hint').textContent = mode === 'unlock' ? `@${state.username}` : passcodeCopy[mode].hint;
  $('passcode-message').textContent = message;
  const foot = $('passcode-foot');
  foot.innerHTML = '';
  if (mode === 'confirm') {
    foot.append(linkButton('Start again', () => startPasscode('choose')));
  } else {
    foot.append('Not you? ', linkButton('Sign out', signOut));
  }
  renderDots();
  show('screen-passcode');
}

function linkButton(label, run) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'r-link-btn';
  button.textContent = label;
  button.addEventListener('click', run);
  return button;
}

function renderDots(error = false) {
  const dots = $('passcode-dots');
  dots.classList.toggle('is-error', error);
  [...dots.children].forEach((dot, i) => dot.classList.toggle('is-filled', i < passcode.digits.length));
}

function press(key) {
  if (passcode.busy || $('screen-passcode').hidden) return;
  if (key === 'erase') {
    passcode.digits = passcode.digits.slice(0, -1);
  } else if (passcode.digits.length < 6) {
    passcode.digits += key;
    $('passcode-message').textContent = '';
  }
  renderDots();
  if (passcode.digits.length === 6) submitPasscode();
}

async function submitPasscode() {
  const digits = passcode.digits;
  if (passcode.mode === 'choose') {
    passcode.first = digits;
    startPasscode('confirm');
    return;
  }
  if (passcode.mode === 'confirm' && digits !== passcode.first) {
    passcode.first = '';
    shake();
    startPasscode('choose', 'Those didn’t match. Choose your passcode again.');
    return;
  }

  passcode.busy = true;
  $('passcode-message').textContent = passcode.mode === 'unlock' ? 'Unlocking…' : 'Setting up…';
  try {
    if (passcode.mode === 'confirm') {
      const salt = hex(crypto.getRandomValues(new Uint8Array(32)));
      const iterations = 100000;
      const { key, verifier } = await deriveKey(digits, salt, iterations);
      await postJSON('/api/setup', { salt, verifier, iterations });
      state.vault = { setup: true, salt, verifier, iterations, entries: [] };
      state.key = key;
    } else {
      const { key, verifier } = await deriveKey(digits, state.vault.salt, state.vault.iterations || 100000);
      if (verifier !== state.vault.verifier) {
        passcode.digits = '';
        shake();
        $('passcode-message').textContent = 'That’s not your passcode. Try again.';
        return;
      }
      state.key = key;
    }
    passcode.first = '';
    await unlocked();
  } catch (error) {
    passcode.digits = '';
    renderDots();
    $('passcode-message').textContent = error.message;
  } finally {
    passcode.busy = false;
  }
}

function shake() {
  renderDots(true);
  setTimeout(() => renderDots(), 450);
}

async function unlocked() {
  state.codes = await Promise.all((state.vault.entries || []).map(async (entry) => ({ id: entry.id, encrypted: entry, code: await decrypt(entry) })));
  show('screen-codes');
  render();
  tick();
}

function lock() {
  closeMenus();
  for (const id of dialogs) if (!$(id).hidden) closeDialog(id);
  stopScanner();
  state.key = null;
  state.codes = [];
  $('code-list').replaceChildren();
  startPasscode('unlock');
}

async function signOut() {
  await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
  location.replace('/?reason=signed-out');
}

/* ---------- Codes ---------- */

function label(code) {
  return code?.issuer || code?.name || 'Code';
}

function visibleCodes() {
  const q = state.query;
  return state.codes.filter(({ code }) => !q
    || (code?.issuer || '').toLowerCase().includes(q)
    || (code?.name || '').toLowerCase().includes(q));
}

function render() {
  const list = $('code-list');
  const visible = visibleCodes();
  list.replaceChildren(...visible.map(codeRow));
  const count = state.codes.length;
  $('code-count').textContent = count ? `${count} ${count === 1 ? 'code' : 'codes'}` : '';
  $('search-wrap').hidden = count < 2;
  $('add-button').hidden = count === 0;

  if (count === 0) {
    showState({
      icon: 'key-round',
      title: 'No codes yet',
      text: 'When a site offers two-factor sign-in, choose the authenticator app option and scan its QR code here.',
      action: { label: 'Add your first code', run: openAdd },
    });
  } else if (visible.length === 0) {
    showState({
      icon: 'search',
      title: `Nothing matches "${state.query}"`,
      text: 'Search looks at service and account names.',
      action: { label: 'Clear search', run: () => { $('search').value = ''; state.query = ''; render(); $('search').focus(); } },
    });
  } else {
    $('codes-state').hidden = true;
  }
  paintCodes();
}

function showState({ icon: name, title, text, action }) {
  $('codes-state').hidden = false;
  $('codes-state-icon').setAttribute('href', `/static/icons.svg#${name}`);
  $('codes-state-title').textContent = title;
  $('codes-state-text').textContent = text;
  const button = $('codes-state-action');
  button.hidden = !action;
  if (action) {
    button.textContent = action.label;
    button.onclick = action.run;
  }
}

function codeRow({ id, code }) {
  const li = document.createElement('li');
  li.dataset.id = id;
  li.className = `code${state.fresh === id ? ' is-fresh' : ''}`;
  if (!code) {
    li.innerHTML = `
      <div class="code__mark code__mark--broken">${icon('circle-alert')}</div>
      <div class="code__text"><span class="code__issuer">This code can't be read</span><span class="code__name">It may have been saved with another passcode.</span></div>
      <button class="r-icon-btn r-icon-btn--sm code__more" type="button" aria-haspopup="menu" aria-expanded="false" aria-label="More actions">${icon('ellipsis')}</button>`;
  } else {
    li.innerHTML = `
      <div class="code__mark" aria-hidden="true"></div>
      <div class="code__text"><span class="code__issuer"></span><span class="code__name"></span></div>
      <button class="code__value" type="button"><span class="code__digits"></span><span class="code__copied" aria-hidden="true">Copied</span></button>
      <span class="code__timer" aria-hidden="true"><svg viewBox="0 0 24 24"><circle class="code__track" cx="12" cy="12" r="10"/><circle class="code__sweep" cx="12" cy="12" r="10" pathLength="100"/></svg><span class="code__seconds"></span></span>
      <button class="r-icon-btn r-icon-btn--sm code__more" type="button" aria-haspopup="menu" aria-expanded="false">${icon('ellipsis')}</button>`;
    li.querySelector('.code__mark').textContent = label(code).trim().charAt(0).toUpperCase();
    li.querySelector('.code__issuer').textContent = label(code);
    li.querySelector('.code__name').textContent = code.issuer ? code.name || '' : '';
    li.querySelector('.code__value').addEventListener('click', () => copyCode(id));
    li.querySelector('.code__more').setAttribute('aria-label', `More actions for ${label(code)}`);
  }
  const more = li.querySelector('.code__more');
  more.addEventListener('click', (event) => {
    event.stopPropagation();
    toggleCodeMenu(id, more);
  });
  return li;
}

const codeCache = new Map();

async function currentCode(code) {
  const period = Number(code.period) || 30;
  const step = Math.floor(Date.now() / 1000 / period);
  const cacheKey = `${code.secret}:${code.digits}:${code.algorithm}:${period}:${step}`;
  if (!codeCache.has(cacheKey)) {
    if (codeCache.size > 200) codeCache.clear();
    codeCache.set(cacheKey, await TOTP.generate(code.secret, Number(code.digits) || 6, code.algorithm || 'SHA-1', period));
  }
  return codeCache.get(cacheKey);
}

function spaced(digits) {
  const half = Math.ceil(digits.length / 2);
  return `${digits.slice(0, half)} ${digits.slice(half)}`;
}

async function paintCodes() {
  for (const li of $('code-list').children) {
    const entry = state.codes.find((c) => c.id === li.dataset.id);
    if (!entry?.code) continue;
    const period = Number(entry.code.period) || 30;
    const left = TOTP.getRemainingSeconds(period);
    const digits = await currentCode(entry.code).catch(() => null);
    const value = li.querySelector('.code__value');
    if (!digits) {
      li.querySelector('.code__digits').textContent = '— —';
      value.disabled = true;
      continue;
    }
    li.querySelector('.code__digits').textContent = spaced(digits);
    value.setAttribute('aria-label', `${label(entry.code)} code ${digits.split('').join(' ')}, ${left} seconds left. Copy`);
    li.querySelector('.code__seconds').textContent = left;
    li.querySelector('.code__sweep').style.strokeDashoffset = String(100 - (left / period) * 100);
    li.classList.toggle('is-ending', left <= 5);
  }
}

let ticking = null;
function tick() {
  clearTimeout(ticking);
  if (!state.key) return;
  paintCodes();
  ticking = setTimeout(tick, 1000 - (Date.now() % 1000));
}

async function copyCode(id) {
  const entry = state.codes.find((c) => c.id === id);
  if (!entry?.code) return;
  const digits = await currentCode(entry.code);
  try {
    await navigator.clipboard.writeText(digits);
  } catch {
    toast(`Your browser didn't allow copying. The code is ${spaced(digits)}.`, { tone: 'danger' });
    return;
  }
  const li = [...$('code-list').children].find((el) => el.dataset.id === id);
  li?.classList.add('is-copied');
  setTimeout(() => li?.classList.remove('is-copied'), 1400);
  toast(`Copied the ${label(entry.code)} code`);
}

function markFresh(id) {
  state.fresh = id;
  render();
  setTimeout(() => {
    if (state.fresh !== id) return;
    state.fresh = null;
    document.querySelector('.code.is-fresh')?.classList.remove('is-fresh');
  }, 4000);
}

/* ---------- Saving ---------- */

function newId() {
  return crypto.randomUUID ? crypto.randomUUID() : hex(crypto.getRandomValues(new Uint8Array(16)));
}

function duplicateOf(secret) {
  const clean = secret.toUpperCase().replace(/[\s=]/g, '');
  return state.codes.find(({ code }) => code && code.secret.toUpperCase().replace(/[\s=]/g, '') === clean);
}

async function saveCode(id, code) {
  const encrypted = await encrypt(id, code);
  await postJSON('/api/entry', encrypted);
  const existing = state.codes.find((c) => c.id === id);
  if (existing) {
    existing.encrypted = encrypted;
    existing.code = code;
  } else {
    state.codes.push({ id, encrypted, code });
  }
}

async function addCode(code) {
  const twin = duplicateOf(code.secret);
  if (twin) throw new Error(`You've already added this code, as ${label(twin.code)}.`);
  const id = newId();
  await saveCode(id, code);
  closeDialog('add-dialog');
  markFresh(id);
  toast(`Added ${label(code)}`, { action: { label: 'Undo', run: () => removeCode(id, { undo: true }) } });
}

async function removeCode(id, { undo = false } = {}) {
  const entry = state.codes.find((c) => c.id === id);
  try {
    await api(`/api/entry?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
  } catch (error) {
    toast(error.message, { tone: 'danger' });
    return false;
  }
  state.codes = state.codes.filter((c) => c.id !== id);
  render();
  if (undo) {
    toast(`Removed ${label(entry?.code)}`);
  } else {
    toast(`Deleted ${label(entry?.code)}`, {
      action: {
        label: 'Undo',
        run: async () => {
          try {
            await postJSON('/api/entry', entry.encrypted);
            state.codes.push(entry);
            markFresh(id);
            toast(`Restored ${label(entry.code)}`);
          } catch (error) {
            toast(error.message, { tone: 'danger' });
          }
        },
      },
    });
  }
  return true;
}

/* ---------- Adding ---------- */

let scanner = null;
let scanning = false;

function openAdd() {
  openDialog('add-dialog');
  const camera = !!navigator.mediaDevices?.getUserMedia;
  $('way-scan').hidden = !camera;
  chooseWay(camera ? 'scan' : 'key');
}

function chooseWay(way) {
  for (const name of ['scan', 'image', 'key']) {
    $(`way-${name}`).setAttribute('aria-selected', String(name === way));
    $(`way-${name}`).tabIndex = name === way ? 0 : -1;
    $(`panel-${name}`).hidden = name !== way;
  }
  if (way === 'scan') startScanner();
  else stopScanner();
  if (way === 'key') $('key-issuer').focus();
}

function setScanHint(text, isError = false) {
  $('scan-hint').textContent = text;
  $('scan-hint').className = isError ? 'r-error' : 'r-hint';
}

async function startScanner() {
  if (scanning) return;
  if (!window.Html5Qrcode) {
    setScanHint('The scanner is still loading. Try again in a moment.', true);
    return;
  }
  setScanHint('Point your camera at the QR code the site shows when you turn on two-factor sign-in.');
  scanner = scanner || new Html5Qrcode('scanner', { verbose: false });
  scanning = true;
  try {
    await scanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: (w, h) => { const s = Math.floor(Math.min(w, h) * 0.7); return { width: s, height: s }; } }, onScan, () => {});
  } catch (error) {
    scanning = false;
    const denied = /permission|notallowed/i.test(String(error?.name || error));
    setScanHint(denied
      ? "roturAuth can't use your camera. Allow it in your browser's site settings, or add the code from a screenshot or its setup key."
      : "Couldn't find a camera. Add the code from a screenshot or its setup key instead.", true);
  }
}

function stopScanner() {
  if (!scanning || !scanner) return;
  scanning = false;
  scanner.stop().catch(() => {});
}

async function onScan(text) {
  if (!scanning) return;
  stopScanner();
  try {
    await addFromUri(text);
  } catch (error) {
    setScanHint(error.message, true);
    setTimeout(() => { if (!$('add-dialog').hidden && !$('panel-scan').hidden) startScanner(); }, 2500);
  }
}

async function addFromUri(text) {
  const parsed = TOTP.parseOtpAuthUrl(text);
  if (!parsed?.secret) throw new Error("That QR code isn't a two-factor code. Look for the one shown when you turn on an authenticator app.");
  await addCode({ issuer: parsed.issuer, name: parsed.name, secret: parsed.secret.toUpperCase(), digits: parsed.digits, algorithm: parsed.algorithm, period: parsed.period });
}

async function addFromImage(file) {
  if (!file) return;
  const drop = $('drop');
  drop.classList.add('is-busy');
  try {
    if (!window.Html5Qrcode) throw new Error('The QR reader is still loading. Try again in a moment.');
    scanner = scanner || new Html5Qrcode('scanner', { verbose: false });
    const text = await scanner.scanFile(file, false).catch(() => { throw new Error("Couldn't find a QR code in that image. Try a sharper screenshot, or enter the setup key."); });
    await addFromUri(text);
  } catch (error) {
    toast(error.message, { tone: 'danger' });
  } finally {
    drop.classList.remove('is-busy');
    $('qr-file').value = '';
  }
}

async function addFromKey(event) {
  event.preventDefault();
  const issuer = $('key-issuer').value.trim();
  const name = $('key-name').value.trim();
  const secret = $('key-secret').value.toUpperCase().replace(/[\s=-]/g, '');
  const error = $('key-error');
  const fail = (message, field) => {
    error.textContent = message;
    error.hidden = false;
    $(field).setAttribute('aria-invalid', 'true');
    $(field).focus();
  };
  error.hidden = true;
  for (const id of ['key-issuer', 'key-secret']) $(id).removeAttribute('aria-invalid');
  if (!issuer) return fail('Say which service this code is for, like GitHub.', 'key-issuer');
  if (!secret) return fail('Enter the setup key shown under the QR code.', 'key-secret');
  if (!/^[A-Z2-7]{16,}$/.test(secret)) return fail('That setup key has a character it can’t have. Keys use the letters A to Z and the numbers 2 to 7.', 'key-secret');

  const submit = $('key-submit');
  submit.disabled = true;
  submit.setAttribute('aria-busy', 'true');
  try {
    await addCode({ issuer, name, secret, digits: Number($('key-digits').value), algorithm: $('key-algorithm').value, period: Number($('key-period').value) });
    $('panel-key').reset();
  } catch (err) {
    fail(err.message, 'key-secret');
  } finally {
    submit.disabled = false;
    submit.removeAttribute('aria-busy');
  }
}

/* ---------- Rename and delete ---------- */

function openEdit(id) {
  const entry = state.codes.find((c) => c.id === id);
  if (!entry?.code) return;
  $('edit-issuer').value = entry.code.issuer || '';
  $('edit-name').value = entry.code.name || '';
  $('edit-error').hidden = true;
  const form = $('edit-dialog').querySelector('form');
  form.onsubmit = async (event) => {
    event.preventDefault();
    const issuer = $('edit-issuer').value.trim();
    const name = $('edit-name').value.trim();
    if (!issuer) {
      $('edit-error').textContent = 'Say which service this code is for.';
      $('edit-error').hidden = false;
      $('edit-issuer').focus();
      return;
    }
    const before = { ...entry.code };
    const submit = $('edit-submit');
    submit.disabled = true;
    submit.setAttribute('aria-busy', 'true');
    try {
      await saveCode(id, { ...entry.code, issuer, name });
      closeDialog('edit-dialog');
      markFresh(id);
      toast(`Renamed to ${issuer}`, {
        action: { label: 'Undo', run: () => saveCode(id, before).then(() => { markFresh(id); toast(`Changed back to ${label(before)}`); }).catch((e) => toast(e.message, { tone: 'danger' })) },
      });
    } catch (error) {
      $('edit-error').textContent = error.message;
      $('edit-error').hidden = false;
    } finally {
      submit.disabled = false;
      submit.removeAttribute('aria-busy');
    }
  };
  openDialog('edit-dialog');
  $('edit-issuer').focus();
  $('edit-issuer').select();
}

function openDelete(id) {
  const entry = state.codes.find((c) => c.id === id);
  const name = label(entry?.code);
  $('delete-title').textContent = entry?.code ? `Delete the ${name} code?` : 'Delete this code?';
  $('delete-text').textContent = entry?.code
    ? `You won't be able to make ${name} codes here any more. Before you delete it, turn off two-factor sign-in on ${name} or make sure you have another way in.`
    : "It can't be read, so it can't make codes. Deleting it can't make things worse.";
  $('delete-submit').onclick = async () => {
    const submit = $('delete-submit');
    submit.disabled = true;
    submit.setAttribute('aria-busy', 'true');
    const done = await removeCode(id);
    submit.disabled = false;
    submit.removeAttribute('aria-busy');
    if (done) closeDialog('delete-dialog');
  };
  openDialog('delete-dialog');
  $('delete-submit').focus();
}

/* ---------- Backup ---------- */

function downloadBackup() {
  const codes = state.codes.filter((c) => c.code).map(({ id, code }) => ({ id, ...code }));
  const blob = new Blob([JSON.stringify({ version: 1, exported: new Date().toISOString(), entries: codes }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `roturauth-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`Downloaded a backup of ${codes.length} ${codes.length === 1 ? 'code' : 'codes'}`);
}

async function restoreBackup(file) {
  if (!file) return;
  try {
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      throw new Error("That file isn't a roturAuth backup.");
    }
    const list = Array.isArray(parsed) ? parsed : parsed.entries || parsed.db;
    if (!Array.isArray(list)) throw new Error("That file isn't a roturAuth backup.");
    const seen = new Set(state.codes.filter((c) => c.code).map((c) => c.code.secret.toUpperCase()));
    const fresh = [];
    let skipped = 0;
    for (const item of list) {
      const secret = String(item?.secret || '').toUpperCase().replace(/[\s=]/g, '');
      if (!/^[A-Z2-7]+$/.test(secret) || seen.has(secret)) {
        skipped++;
        continue;
      }
      seen.add(secret);
      const code = { issuer: String(item.issuer || ''), name: String(item.name || ''), secret, digits: Number(item.digits) || 6, algorithm: item.algorithm || 'SHA-1', period: Number(item.period) || 30 };
      const id = newId();
      fresh.push({ id, code, encrypted: await encrypt(id, code) });
    }
    if (fresh.length === 0) {
      toast(skipped ? 'Every code in that backup is already here.' : 'That backup has no codes in it.');
      return;
    }
    await postJSON('/api/entries', { entries: fresh.map((f) => f.encrypted) });
    state.codes.push(...fresh);
    closeDialog('settings-dialog');
    render();
    toast(`Restored ${fresh.length} ${fresh.length === 1 ? 'code' : 'codes'}${skipped ? `. ${skipped} were already here` : ''}`);
  } catch (error) {
    toast(error.message, { tone: 'danger' });
  } finally {
    $('restore-file').value = '';
  }
}

/* ---------- Settings ---------- */

function renderSwatches() {
  const current = accent.current;
  const isPreset = accent.swatches.some((s) => s.hex === current);
  const swatches = accent.swatches.map(({ hex: value, name }) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'r-swatch';
    button.setAttribute('role', 'radio');
    button.setAttribute('aria-checked', String(value === current));
    button.setAttribute('aria-label', name);
    button.title = name;
    button.style.setProperty('--swatch', value);
    button.addEventListener('click', () => {
      accent.set(value);
      renderSwatches();
      $('swatches').querySelector('[aria-checked="true"]')?.focus();
    });
    return button;
  });
  const custom = document.createElement('label');
  custom.className = 'r-swatch r-swatch--custom';
  custom.title = 'Custom colour';
  custom.dataset.checked = String(!isPreset);
  if (isPreset) custom.innerHTML = icon('plus');
  else custom.style.setProperty('--swatch', current);
  const input = document.createElement('input');
  input.type = 'color';
  input.value = current;
  input.setAttribute('aria-label', 'Custom colour');
  input.addEventListener('input', () => {
    accent.set(input.value);
    custom.style.setProperty('--swatch', accent.current);
    custom.dataset.checked = 'true';
    custom.querySelector('svg')?.remove();
    $('swatches').querySelectorAll('[role="radio"]').forEach((el) => el.setAttribute('aria-checked', 'false'));
  });
  custom.append(input);
  $('swatches').replaceChildren(...swatches, custom);
}

function openSettings() {
  renderSwatches();
  // Focus returns to the account button on close, since the menu item is hidden by then.
  $('account-button').focus();
  openDialog('settings-dialog');
  $('swatches').querySelector('[aria-checked="true"], input').focus();
}

/* ---------- Menus and dialogs ---------- */

const dialogs = ['add-dialog', 'edit-dialog', 'delete-dialog', 'settings-dialog'];
let dialogReturn = null;

function toggleCodeMenu(id, button) {
  const menu = $('code-menu');
  const wasOpen = state.menuFor === id;
  closeMenus();
  if (wasOpen) return;
  const readable = !!state.codes.find((c) => c.id === id)?.code;
  state.menuFor = id;
  button.setAttribute('aria-expanded', 'true');
  $('menu-copy').parentElement.hidden = !readable;
  $('menu-edit').parentElement.hidden = !readable;
  $('menu-copy').onclick = () => { closeMenus(); copyCode(id); };
  $('menu-edit').onclick = () => { closeMenus(); openEdit(id); };
  $('menu-delete').onclick = () => { closeMenus(); openDelete(id); };
  menu.hidden = false;
  const box = button.getBoundingClientRect();
  const width = menu.offsetWidth;
  menu.style.top = `${box.bottom + window.scrollY + 6}px`;
  menu.style.left = `${Math.max(12, Math.min(box.right - width, window.innerWidth - width - 12)) + window.scrollX}px`;
  menu.returnTo = button;
  menu.querySelector('li:not([hidden]) [role="menuitem"]').focus();
}

function closeMenus() {
  const menu = $('code-menu');
  if (!menu.hidden && menu.returnTo && menu.contains(document.activeElement)) menu.returnTo.focus();
  menu.hidden = true;
  state.menuFor = null;
  document.querySelectorAll('[aria-expanded="true"]').forEach((el) => el.setAttribute('aria-expanded', 'false'));
  $('account-menu').hidden = true;
}

function menuKeys(event) {
  if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
  event.preventDefault();
  const items = [...event.currentTarget.querySelectorAll('[role="menuitem"]')].filter((el) => el.offsetParent);
  const at = items.indexOf(document.activeElement);
  items[(at + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length].focus();
}

function openDialog(id) {
  closeMenus();
  dialogReturn = document.activeElement;
  $(id).hidden = false;
}

function closeDialog(id) {
  $(id).hidden = true;
  if (id === 'add-dialog') stopScanner();
  dialogReturn?.focus?.();
}

/* ---------- Toasts ---------- */

function toast(message, { tone, action } = {}) {
  const region = $('toasts');
  region.replaceChildren();
  const el = document.createElement('div');
  el.className = `r-toast${tone ? ` r-toast--${tone}` : ''}`;
  el.innerHTML = icon(tone === 'danger' ? 'circle-alert' : 'check');
  const text = document.createElement('span');
  text.textContent = message;
  el.append(text);
  if (action) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'r-link-btn toast-action';
    button.textContent = action.label;
    button.addEventListener('click', () => { el.remove(); action.run(); });
    el.append(button);
  }
  region.append(el);
  setTimeout(() => el.remove(), action ? 8000 : 4000);
}

/* ---------- Wiring ---------- */

function bind() {
  $('numpad').addEventListener('click', (event) => {
    const key = event.target.closest('button');
    if (key) press(key.dataset.erase !== undefined ? 'erase' : key.dataset.digit);
  });
  document.addEventListener('keydown', (event) => {
    if (!$('screen-passcode').hidden && !event.metaKey && !event.ctrlKey && !event.altKey) {
      if (/^[0-9]$/.test(event.key)) press(event.key);
      else if (event.key === 'Backspace') press('erase');
      return;
    }
    if (event.key === 'Escape') {
      for (const id of dialogs) if (!$(id).hidden) return closeDialog(id);
      closeMenus();
    }
  });

  $('add-button').addEventListener('click', openAdd);
  for (const way of ['scan', 'image', 'key']) $(`way-${way}`).addEventListener('click', () => chooseWay(way));
  $('add-dialog').querySelector('.add__ways').addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
    const tabs = [...event.currentTarget.querySelectorAll('[role="tab"]')].filter((t) => !t.hidden);
    const at = tabs.indexOf(document.activeElement);
    const next = tabs[(at + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
    next.focus();
    next.click();
  });
  $('qr-file').addEventListener('change', (event) => addFromImage(event.target.files[0]));
  const drop = $('drop');
  drop.addEventListener('dragover', (event) => { event.preventDefault(); drop.classList.add('is-over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('is-over'));
  drop.addEventListener('drop', (event) => { event.preventDefault(); drop.classList.remove('is-over'); addFromImage(event.dataTransfer.files[0]); });
  $('panel-key').addEventListener('submit', addFromKey);

  $('search').addEventListener('input', (event) => { state.query = event.target.value.trim().toLowerCase(); render(); });

  $('account-button').addEventListener('click', (event) => {
    event.stopPropagation();
    const open = $('account-menu').hidden;
    closeMenus();
    $('account-menu').hidden = !open;
    $('account-button').setAttribute('aria-expanded', String(open));
    if (open) $('account-menu').querySelector('[role="menuitem"]').focus();
  });
  $('open-settings').addEventListener('click', openSettings);
  $('lock').addEventListener('click', lock);
  $('sign-out').addEventListener('click', signOut);
  $('backup').addEventListener('click', downloadBackup);
  $('restore-file').addEventListener('change', (event) => restoreBackup(event.target.files[0]));

  for (const menu of [$('code-menu'), $('account-menu')]) {
    menu.addEventListener('click', (event) => event.stopPropagation());
    menu.addEventListener('keydown', menuKeys);
  }
  document.addEventListener('click', closeMenus);
  window.addEventListener('resize', closeMenus);
  for (const id of dialogs) {
    $(id).addEventListener('click', (event) => {
      if (event.target === $(id) || event.target.closest('[data-close]')) closeDialog(id);
    });
  }

  const online = () => { $('offline-note').hidden = navigator.onLine; };
  window.addEventListener('online', online);
  window.addEventListener('offline', online);
  online();
  // Codes change on the half-minute even while the tab sleeps, so catch up when it's back.
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
}

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/static/sw.js').catch(() => {});
bind();
open();

const $ = (id) => document.getElementById(id);
const pending = 'roturauth.sign-in';

function randomState() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function setBusy(busy) {
  const button = $('sign-in');
  button.disabled = busy;
  button.toggleAttribute('aria-busy', busy);
  button.innerHTML = busy ? '<span class="r-spinner" aria-hidden="true"></span>Signing you in' : 'Sign in with Rotur';
}

function showError(message) {
  setBusy(false);
  $('sign-in-note').textContent = '';
  $('sign-in-error').textContent = message;
  $('sign-in-error').hidden = false;
}

function start() {
  const state = randomState();
  sessionStorage.setItem(pending, state);
  const url = new URL('https://rotur.dev/auth');
  url.searchParams.set('return_to', `${location.origin}/auth`);
  url.searchParams.set('state', state);
  url.searchParams.set('response_mode', 'fragment');
  // Only what the vault needs: it is a file in your Rotur files. Not files:app, which would
  // hide the vaults people already have.
  url.searchParams.set('requires', 'files:view,files:manage');
  setBusy(true);
  location.assign(url);
}

async function finish(token) {
  setBusy(true);
  try {
    const res = await fetch('/api/auth', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "roturAuth couldn't start your session.");
    location.replace('/');
  } catch (error) {
    const offline = error instanceof TypeError;
    showError(offline ? "Couldn't reach roturAuth. Check your connection, then sign in again." : error.message);
  }
}

function handleReturn() {
  const answer = new URLSearchParams(location.hash.slice(1));
  if (!answer.has('rotur_token') && !answer.has('rotur_error')) return false;
  history.replaceState(null, '', location.pathname);
  const state = sessionStorage.getItem(pending);
  sessionStorage.removeItem(pending);

  if (!state || answer.get('state') !== state) {
    showError("That sign-in didn't start on this page, so it was ignored. Sign in again.");
  } else if (answer.get('rotur_error') === 'access_denied') {
    $('sign-in-note').textContent = 'You cancelled signing in. Your codes stay as they are.';
  } else if (answer.has('rotur_error')) {
    showError('Rotur couldn’t finish signing you in. Try again.');
  } else {
    finish(answer.get('rotur_token'));
  }
  return true;
}

$('sign-in').addEventListener('click', start);
if (!handleReturn() && new URLSearchParams(location.search).get('reason') === 'signed-out') {
  $('sign-in-note').textContent = "You've signed out.";
}
window.addEventListener('pageshow', (event) => {
  if (event.persisted) setBusy(false);
});

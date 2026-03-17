window.Unlock = {
  passcode: '',
  salt: null,
  iterations: 100000,
  storedVerifier: null,

  async init() {
    const statusRes = await fetch('/api/status');
    const status = await statusRes.json();

    if (!status.authenticated) {
      window.location.href = '/auth';
      return;
    }

    const verifyRes = await fetch('/api/verify-params');
    const verifyData = await verifyRes.json();

    if (verifyData.salt) {
      this.salt = verifyData.salt;
      this.iterations = verifyData.iterations || 100000;
      this.storedVerifier = verifyData.verifier;
    }

    this.setupNumpad();
    lucide.createIcons();
  },

  setupNumpad() {
    document.querySelectorAll('.numpad-btn[data-digit]').forEach(btn => {
      btn.addEventListener('click', () => {
        const digit = btn.dataset.digit;

        if (digit === 'backspace') {
          this.passcode = this.passcode.slice(0, -1);
        } else if (this.passcode.length < 6) {
          this.passcode += digit;
        }

        this.updateDisplay();

        if (this.passcode.length === 6) {
          this.verifyPasscode();
        }
      });
    });
  },

  updateDisplay() {
    document.querySelectorAll('.passcode-dot').forEach((dot, i) => {
      dot.classList.toggle('filled', i < this.passcode.length);
    });
  },

  async deriveKeyAndVerifier(passcode, saltHex, iterations) {
    const encoder = new TextEncoder();
    const saltBytes = this.hexToBytes(saltHex);

    const passcodeKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passcode),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: iterations,
        hash: 'SHA-256'
      },
      passcodeKey,
      256
    );

    const hash = await crypto.subtle.digest('SHA-256', derivedBits);
    return this.bytesToHex(new Uint8Array(hash));
  },

  hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  },

  bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  async verifyPasscode() {
    const errorEl = document.getElementById('error-message');
    const lockoutEl = document.getElementById('lockout-message');
    errorEl.style.display = 'none';
    lockoutEl.style.display = 'none';

    try {
      if (!this.salt || !this.storedVerifier) {
        this.showError('Setup required');
        return;
      }

      const verifier = await this.deriveKeyAndVerifier(this.passcode, this.salt, this.iterations);

      if (verifier !== this.storedVerifier) {
        this.showError('Invalid passcode');
        this.passcode = '';
        this.updateDisplay();
        return;
      }

      sessionStorage.setItem('derivedKey', this.passcode);
      sessionStorage.setItem('salt', this.salt);
      sessionStorage.setItem('iterations', this.iterations.toString());

      await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verified: true })
      });

      window.location.replace('/');
    } catch (e) {
      this.showError('Network error');
      this.passcode = '';
      this.updateDisplay();
    }
  },

  showError(message, remaining) {
    const errorEl = document.getElementById('error-message');
    const textEl = document.getElementById('error-text');

    textEl.textContent = remaining ? `${message} (${remaining} attempts remaining)` : message;
    errorEl.style.display = 'flex';

    document.querySelectorAll('.passcode-dot').forEach(dot => {
      dot.classList.add('error');
      setTimeout(() => dot.classList.remove('error'), 500);
    });
  },

  showLockout(seconds) {
    const lockoutEl = document.getElementById('lockout-message');
    const timeEl = document.getElementById('lockout-time');

    lockoutEl.style.display = 'flex';
    timeEl.textContent = seconds;

    const interval = setInterval(() => {
      seconds--;
      timeEl.textContent = seconds;
      if (seconds <= 0) {
        clearInterval(interval);
        lockoutEl.style.display = 'none';
        this.passcode = '';
        this.updateDisplay();
      }
    }, 1000);
  }
};

document.addEventListener('DOMContentLoaded', () => Unlock.init());

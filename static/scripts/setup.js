window.Setup = {
    passcode: '',
    confirmPasscode: '',
    step: 1,
    salt: null,
    iterations: 100000,

    async init() {
        const statusRes = await fetch('/api/status');
        const status = await statusRes.json();

        if (!status.authenticated) {
            window.location.href = '/auth';
            return;
        }

        this.generateSalt();
        this.setupNumpad();
        lucide.createIcons();
    },

    generateSalt() {
        const saltBytes = crypto.getRandomValues(new Uint8Array(32));
        this.salt = this.bytesToHex(saltBytes);
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
                    this.handleComplete();
                }
            });
        });
    },

    updateDisplay() {
        document.querySelectorAll('.passcode-dot').forEach((dot, i) => {
            dot.classList.toggle('filled', i < this.passcode.length);
        });
    },

    handleComplete() {
        if (this.step === 1) {
            this.confirmPasscode = this.passcode;
            this.passcode = '';
            this.step = 2;
            this.updateUI();
            this.updateDisplay();
        } else {
            this.verifyAndSave();
        }
    },

    updateUI() {
        const titleEl = document.getElementById('setup-title');
        const subtitleEl = document.getElementById('setup-subtitle');
        const iconEl = document.getElementById('setup-icon');

        document.querySelector('.progress-step[data-step="1"]').classList.remove('active');
        document.querySelector('.progress-step[data-step="1"]').classList.add('completed');
        document.querySelector('.progress-step[data-step="2"]').classList.add('active');

        titleEl.textContent = 'Confirm Passcode';
        subtitleEl.textContent = 'Enter your passcode again to confirm';
        iconEl.innerHTML = '<i data-lucide="shield-check"></i>';
        lucide.createIcons();
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

    async verifyAndSave() {
        const errorEl = document.getElementById('error-message');
        const textEl = document.getElementById('error-text');

        if (this.passcode !== this.confirmPasscode) {
            textEl.textContent = 'Passcodes do not match';
            errorEl.style.display = 'flex';
            this.passcode = '';
            this.step = 1;
            this.updateDisplay();
            this.resetUI();
            return;
        }

        errorEl.style.display = 'none';

        const verifier = await this.deriveKeyAndVerifier(this.passcode, this.salt, this.iterations);

        try {
            const res = await fetch('/api/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    salt: this.salt,
                    verifier: verifier,
                    iterations: this.iterations
                })
            });

            const data = await res.json();

            if (data.ok) {
                sessionStorage.setItem('derivedKey', this.passcode);
                sessionStorage.setItem('salt', this.salt);
                sessionStorage.setItem('iterations', this.iterations);
                window.location.href = '/';
            } else {
                textEl.textContent = data.error || 'Setup failed';
                errorEl.style.display = 'flex';
                this.passcode = '';
                this.step = 1;
                this.updateDisplay();
                this.resetUI();
            }
        } catch (e) {
            textEl.textContent = 'Network error';
            errorEl.style.display = 'flex';
            this.passcode = '';
            this.updateDisplay();
        }
    },

    resetUI() {
        document.querySelector('.progress-step[data-step="1"]').classList.add('active');
        document.querySelector('.progress-step[data-step="1"]').classList.remove('completed');
        document.querySelector('.progress-step[data-step="2"]').classList.remove('active');

        document.getElementById('setup-title').textContent = 'Create Passcode';
        document.getElementById('setup-subtitle').textContent = 'Choose a 6-digit passcode to secure your authenticator';
        document.getElementById('setup-icon').innerHTML = '<i data-lucide="shield-plus"></i>';
        lucide.createIcons();
    }
};

document.addEventListener('DOMContentLoaded', () => Setup.init());

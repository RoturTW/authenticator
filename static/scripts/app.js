(function() {
  let _key = null;
  let entries = [];
  let decryptedEntries = [];
  let qrScanner = null;
  let currentView = 'codes';

  const getKey = () => _key;

  async function init() {
    const config = window.AUTH_CONFIG;
    if (!config || !config.entries) return;

    entries = config.entries;

    const derivedKeyPasscode = sessionStorage.getItem('derivedKey');
    if (!derivedKeyPasscode) {
      window.location.href = '/unlock';
      return;
    }

    const salt = sessionStorage.getItem('salt') || config.salt;
    const iterations = parseInt(sessionStorage.getItem('iterations') || config.iterations || 100000);

    _key = await deriveKey(derivedKeyPasscode, salt, iterations);

    for (let i = 0; i < entries.length; i++) {
      const decrypted = await decryptEntry(entries[i], _key);
      decryptedEntries.push(decrypted);
    }

    loadUsername();
    lucide.createIcons();
    renderCodes();
    startTimer();
    setupEventListeners();
    setupMobileNav();
  }

  function loadUsername() {
    const username = document.cookie.split('; ').find(row => row.startsWith('username='));
    if (username) {
      const name = decodeURIComponent(username.split('=')[1]);
      document.getElementById('username').textContent = name;
      document.getElementById('avatar').src = `https://avatars.rotur.dev/${name}`;
      const mobileAvatar = document.getElementById('mobile-avatar');
      if (mobileAvatar) mobileAvatar.src = `https://avatars.rotur.dev/${name}`;
      const profileAvatarImg = document.getElementById('profile-avatar-img');
      if (profileAvatarImg) profileAvatarImg.src = `https://avatars.rotur.dev/${name}`;
      const profileUsername = document.getElementById('profile-username');
      if (profileUsername) profileUsername.textContent = name;
    }
    updateCodeCount();
    loadDriveSize();
  }

  function updateCodeCount() {
    const count = entries.length;
    const codeCount = document.getElementById('code-count');
    if (codeCount) codeCount.textContent = `${count} code${count !== 1 ? 's' : ''}`;
    const totalCodes = document.getElementById('total-codes');
    if (totalCodes) totalCodes.textContent = count;
  }

  async function loadDriveSize() {
    try {
      const res = await fetch('/api/size');
      const data = await res.json();
      if (data.size !== undefined) {
        const driveSize = document.getElementById('drive-size');
        if (driveSize) driveSize.textContent = formatBytes(data.size);
        const sidebarDriveSize = document.getElementById('sidebar-drive-size');
        if (sidebarDriveSize) sidebarDriveSize.textContent = formatBytes(data.size);
      }
    } catch (e) {
      console.error('Failed to load drive size:', e);
    }
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  async function deriveKey(passcode, saltHex, iterations) {
    const encoder = new TextEncoder();
    const saltBytes = hexToBytes(saltHex);

    const passcodeKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passcode),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: iterations || 100000,
        hash: 'SHA-256'
      },
      passcodeKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function decryptEntry(entry, key) {
    try {
      const nonce = hexToBytes(entry.nonce);
      const ciphertext = hexToBytes(entry.ciphertext);

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        ciphertext
      );

      const decoder = new TextDecoder();
      return JSON.parse(decoder.decode(decrypted));
    } catch (e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }

  async function encryptEntry(data, key) {
    const encoder = new TextEncoder();
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      encoder.encode(JSON.stringify(data))
    );

    return {
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(new Uint8Array(encrypted))
    };
  }

  function renderCodes() {
    const list = document.getElementById('codes-list');
    const empty = document.getElementById('empty-state');

    if (entries.length === 0) {
      list.innerHTML = '';
      empty.style.display = 'block';
      return;
    }

    empty.style.display = 'none';
    list.innerHTML = entries.map((entry, i) => {
      const dec = decryptedEntries[i];
      const period = dec?.period || 30;
      const dashArray = 62.83;

      return `
<div class="code-card" data-id="${entry.id}" data-index="${i}" data-period="${period}">
<div class="code-header">
<div class="code-info">
<div class="code-icon">
<i data-lucide="key-round"></i>
</div>
<div class="code-text">
<span class="code-issuer">${escapeHtml(dec?.issuer || 'Account')}</span>
<span class="code-name">${escapeHtml(dec?.name || 'Unknown')}</span>
</div>
</div>
<div class="code-actions">
<button class="action-btn show-btn" title="Show large code">
<i data-lucide="maximize-2"></i>
</button>
<button class="action-btn copy-btn" title="Copy code">
<i data-lucide="copy"></i>
</button>
<button class="action-btn edit-btn" title="Edit">
<i data-lucide="settings"></i>
</button>
</div>
</div>
<div class="code-value">------</div>
<div class="code-footer">
<div class="code-timer">
<div class="timer-ring">
<svg viewBox="0 0 24 24">
<circle class="bg" cx="12" cy="12" r="10" fill="none" stroke-width="2"/>
<circle class="progress" cx="12" cy="12" r="10" fill="none" stroke-width="2"
stroke-dasharray="${dashArray}" stroke-dashoffset="0"/>
</svg>
</div>
<span class="timer-text">${period}s</span>
</div>
</div>
</div>
`;
    }).join('');

    lucide.createIcons();
    refreshCodes();
    setupCodeListeners();
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function startTimer() {
    setInterval(() => refreshCodes(), 1000);
  }

  async function refreshCodes() {
    document.querySelectorAll('.code-card').forEach(async card => {
      const index = parseInt(card.dataset.index);
      const period = parseInt(card.dataset.period) || 30;
      const entry = decryptedEntries[index];

      const timer = card.querySelector('.timer-text');
      const circle = card.querySelector('.progress');
      const codeEl = card.querySelector('.code-value');

      const remaining = TOTP.getRemainingSeconds(period);
      const progress = (remaining / period) * 62.83;

      if (timer) timer.textContent = remaining + 's';
      if (circle) circle.style.strokeDashoffset = 62.83 - progress;

      if (entry && entry.secret) {
        const code = await TOTP.generate(entry.secret, entry.digits, entry.algorithm, period);
        if (codeEl) codeEl.textContent = code;
      }
    });
  }

  function setupEventListeners() {
    document.getElementById('add-btn').addEventListener('click', () => openAddModal());
    document.getElementById('close-modal').addEventListener('click', () => closeAddModal());
    document.getElementById('close-edit-modal').addEventListener('click', () => closeEditModal());
    document.getElementById('close-code-modal').addEventListener('click', () => closeCodeModal());

    const userMenuBtn = document.getElementById('user-menu-btn');
    const userDropdown = document.getElementById('user-dropdown');
    if (userMenuBtn && userDropdown) {
      userMenuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        userDropdown.classList.toggle('active');
      });
      document.addEventListener('click', () => {
        userDropdown.classList.remove('active');
      });
    }

    document.getElementById('logout-btn')?.addEventListener('click', () => logout());

    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => switchView(item.dataset.view));
    });

    document.getElementById('manual-add-btn')?.addEventListener('click', () => addManualEntry());
    document.getElementById('save-edit-btn')?.addEventListener('click', () => saveEdit());
    document.getElementById('delete-code-btn')?.addEventListener('click', () => deleteCurrentEntry());
    document.getElementById('copy-large-code')?.addEventListener('click', () => copyLargeCode());
    document.getElementById('export-btn')?.addEventListener('click', () => exportBackup());

    const importInput = document.getElementById('import-file');
    if (importInput) {
      importInput.addEventListener('change', (e) => importFromFile(e));
    }

    const importBtn = document.getElementById('import-btn');
    if (importBtn) {
      importBtn.addEventListener('click', () => importInput.click());
    }

    const qrUploadArea = document.getElementById('qr-upload-area');
    if (qrUploadArea) {
      qrUploadArea.addEventListener('click', () => {
        document.getElementById('qr-image-file').click();
      });
    }

    const qrImageInput = document.getElementById('qr-image-file');
    if (qrImageInput) {
      qrImageInput.addEventListener('change', (e) => scanQRImage(e));
    }

    document.getElementById('search-input').addEventListener('input', (e) => {
      filterCodes(e.target.value);
    });
  }

  function setupCodeListeners() {
    document.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const card = btn.closest('.code-card');
        const code = card.querySelector('.code-value').textContent;
        copyToClipboard(code);
      });
    });

    document.querySelectorAll('.show-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const card = btn.closest('.code-card');
        const index = parseInt(card.dataset.index);
        showCodeModal(index);
      });
    });

    document.querySelectorAll('.edit-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const card = btn.closest('.code-card');
        openEditModal(card.dataset.id);
      });
    });

    document.querySelectorAll('.code-card').forEach(card => {
      card.addEventListener('click', () => {
        const code = card.querySelector('.code-value').textContent;
        copyToClipboard(code);
      });
    });
  }

  function switchView(view) {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === view);
    });
    document.querySelectorAll('.mobile-nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === view);
    });
    document.querySelectorAll('.view').forEach(v => {
      v.classList.toggle('active', v.id === `${view}-view`);
    });
    currentView = view;
  }

  function setupMobileNav() {
    document.querySelectorAll('.mobile-nav-item').forEach(item => {
      if (item.dataset.view) {
        item.addEventListener('click', () => switchView(item.dataset.view));
      }
    });
    const mobileAddBtn = document.getElementById('mobile-add-btn');
    if (mobileAddBtn) {
      mobileAddBtn.addEventListener('click', () => openAddModal());
    }
    const profileNavBtn = document.getElementById('profile-nav-btn');
    if (profileNavBtn) {
      profileNavBtn.addEventListener('click', () => openProfileModal());
    }
    const closeProfileModalBtn = document.getElementById('close-profile-modal');
    if (closeProfileModalBtn) {
      closeProfileModalBtn.addEventListener('click', () => closeProfileModal());
    }
    const profileLogoutBtn = document.getElementById('profile-logout-btn');
    if (profileLogoutBtn) {
      profileLogoutBtn.addEventListener('click', () => logout());
    }
    const mobileSearchInput = document.getElementById('mobile-search-input');
    if (mobileSearchInput) {
      mobileSearchInput.addEventListener('input', (e) => filterCodes(e.target.value));
    }
  }

  function openProfileModal() {
    document.getElementById('profile-modal').classList.add('active');
  }

  function closeProfileModal() {
    document.getElementById('profile-modal').classList.remove('active');
  }

  function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tab}"]`).classList.add('active');

    document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
    document.getElementById(`${tab}-tab`).style.display = 'block';

    if (tab === 'scan') {
      startQRScanner();
    } else {
      stopQRScanner();
    }
  }

  function openAddModal() {
    document.getElementById('add-modal').classList.add('active');
    startQRScanner();
  }

  function closeAddModal() {
    document.getElementById('add-modal').classList.remove('active');
    stopQRScanner();
  }

  function openEditModal(id) {
    document.getElementById('edit-modal').classList.add('active');
    document.getElementById('edit-modal').dataset.id = id;

    const index = entries.findIndex(e => e.id === id);
    if (index >= 0 && decryptedEntries[index]) {
      document.getElementById('edit-name').value = decryptedEntries[index].name || '';
      document.getElementById('edit-issuer').value = decryptedEntries[index].issuer || '';
    }
  }

  function closeEditModal() {
    document.getElementById('edit-modal').classList.remove('active');
  }

  function showCodeModal(index) {
    const entry = decryptedEntries[index];
    if (!entry) return;

    document.getElementById('code-modal').classList.add('active');
    document.getElementById('code-modal-title').textContent = `${entry.issuer || 'Account'} - ${entry.name || 'Unknown'}`;
    document.getElementById('code-modal').dataset.index = index;
    updateCodeModal();
  }

  function closeCodeModal() {
    document.getElementById('code-modal').classList.remove('active');
  }

  async function updateCodeModal() {
    const modal = document.getElementById('code-modal');
    if (!modal.classList.contains('active')) return;

    const index = parseInt(modal.dataset.index);
    const entry = decryptedEntries[index];
    if (!entry) return;

    const period = entry.period || 30;
    const code = await TOTP.generate(entry.secret, entry.digits, entry.algorithm, period);
    const remaining = TOTP.getRemainingSeconds(period);
    const progress = (remaining / period) * 100;

    document.getElementById('large-code').textContent = code;
    document.getElementById('large-timer-text').textContent = `${remaining}s`;
    document.getElementById('timer-bar-fill').style.width = `${progress}%`;

    setTimeout(() => updateCodeModal(), 1000);
  }

  function copyLargeCode() {
    const code = document.getElementById('large-code').textContent;
    copyToClipboard(code);
  }

  function startQRScanner() {
    if (!document.getElementById('qr-reader')) return;

    if (qrScanner) {
      qrScanner.start(
        { facingMode: 'environment' },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        (decodedText) => {
          handleQRCode(decodedText);
        },
        () => {}
      ).catch(() => {});
      return;
    }

    qrScanner = new Html5Qrcode('qr-reader');
    qrScanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      (decodedText) => {
        handleQRCode(decodedText);
      },
      () => {}
    ).catch(err => {
      console.error('QR Scanner error:', err);
    });
  }

  function stopQRScanner() {
    if (qrScanner) {
      const scanner = qrScanner;
      qrScanner = null;
      scanner.stop().catch(() => {});
    }
  }

  async function scanQRImage(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
      const qrCode = await Html5Qrcode.scanFile(file, true);
      await handleQRCode(qrCode);
    } catch (err) {
      showToast('Could not read QR code from image', 'error');
    }

    event.target.value = '';
  }

  async function handleQRCode(data) {
    const parsed = TOTP.parseOtpAuthUrl(data);

    if (parsed && parsed.secret) {
      await addEntry({
        name: parsed.name,
        issuer: parsed.issuer,
        secret: parsed.secret,
        digits: parsed.digits,
        algorithm: parsed.algorithm,
        period: parsed.period
      });
    } else {
      showToast('Invalid QR code format', 'error');
    }
  }

  async function addManualEntry() {
    const name = document.getElementById('manual-name').value.trim();
    const issuer = document.getElementById('manual-issuer').value.trim();
    const secret = document.getElementById('manual-secret').value.toUpperCase().replace(/\s/g, '');
    const digits = parseInt(document.getElementById('manual-digits').value) || 6;
    const algorithm = document.getElementById('manual-algorithm').value || 'SHA-1';
    const period = parseInt(document.getElementById('manual-period').value) || 30;

    if (!name || !secret) {
      showToast('Please fill in account name and secret', 'error');
      return;
    }

    if (!/^[A-Z2-7]+$/.test(secret)) {
      showToast('Invalid secret key format', 'error');
      return;
    }

    await addEntry({ name, issuer, secret, digits, algorithm, period });
  }

  async function addEntry(entryData) {
    const key = getKey();
    if (!key) {
      showToast('Encryption key not available', 'error');
      return;
    }

    let encrypted;
    try {
      encrypted = await encryptEntry(entryData, key);
    } catch (e) {
      console.error('Encryption error:', e);
      showToast('Failed to encrypt entry', 'error');
      return;
    }

    try {
      const res = await fetch('/api/entry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(encrypted)
      });

      if (!res.ok) {
        showToast(`Server error: ${res.status}`, 'error');
        return;
      }

      const data = await res.json();
      if (data.ok) {
        showToast('Code added successfully', 'success');
        closeAddModal();
        setTimeout(() => location.reload(), 500);
      } else {
        showToast(data.error || 'Failed to add code', 'error');
      }
    } catch (e) {
      console.error('Network error:', e);
      showToast('Network error', 'error');
    }
  }

  async function saveEdit() {
    const key = getKey();
    if (!key) {
      showToast('Encryption key not available', 'error');
      return;
    }

    const id = document.getElementById('edit-modal').dataset.id;
    const index = entries.findIndex(e => e.id === id);

    if (index < 0) return;

    const entry = decryptedEntries[index];
    entry.name = document.getElementById('edit-name').value;
    entry.issuer = document.getElementById('edit-issuer').value;

    const encrypted = await encryptEntry(entry, key);
    encrypted.id = id;

    try {
      await fetch('/api/entry?id=' + id, { method: 'DELETE' });

      const res = await fetch('/api/entry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(encrypted)
      });

      const data = await res.json();
      if (data.ok) {
        showToast('Code updated', 'success');
        closeEditModal();
        setTimeout(() => location.reload(), 500);
      }
    } catch (e) {
      showToast('Network error', 'error');
    }
  }

  async function deleteCurrentEntry() {
    const id = document.getElementById('edit-modal').dataset.id;
    if (!confirm('Are you sure you want to delete this code?')) return;

    try {
      const res = await fetch(`/api/entry?id=${id}`, { method: 'DELETE' });
      const data = await res.json();

      if (data.ok) {
        showToast('Code deleted', 'success');
        closeEditModal();
        setTimeout(() => location.reload(), 500);
      } else {
        showToast(data.error || 'Failed to delete', 'error');
      }
    } catch (e) {
      showToast('Network error', 'error');
    }
  }

  async function exportBackup() {
    const backup = {
      entries: entries.map((entry, i) => ({
        ...decryptedEntries[i],
        id: entry.id
      })),
      exported: new Date().toISOString(),
      version: 1
    };

    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `roturauth-backup-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    showToast('Backup exported', 'success');
  }

  async function importFromFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const backup = JSON.parse(e.target.result);
        const importedEntries = backup.entries || backup.db || backup;

        if (!Array.isArray(importedEntries)) {
          showToast('Invalid backup format', 'error');
          return;
        }

        let imported = 0;
        for (const entry of importedEntries) {
          if (entry.secret) {
            await addEntry({
              name: entry.name || 'Imported',
              issuer: entry.issuer || '',
              secret: entry.secret,
              digits: entry.digits || 6,
              algorithm: entry.algorithm || 'SHA-1',
              period: entry.period || 30
            });
            imported++;
            await new Promise(r => setTimeout(r, 100));
          }
        }

        showToast(`Imported ${imported} codes`, 'success');
        if (imported > 0) {
          setTimeout(() => location.reload(), 1000);
        }
      } catch (err) {
        showToast('Failed to parse backup file', 'error');
        console.error(err);
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  }

  function filterCodes(query) {
    const q = query.toLowerCase();
    document.querySelectorAll('.code-card').forEach(card => {
      const name = card.querySelector('.code-name').textContent.toLowerCase();
      const issuer = card.querySelector('.code-issuer').textContent.toLowerCase();
      card.style.display = (name.includes(q) || issuer.includes(q)) ? '' : 'none';
    });
  }

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied to clipboard', 'success');
    });
  }

  function showToast(message, type) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<i data-lucide="${type === 'success' ? 'check-circle' : 'alert-circle'}"></i><span>${message}</span>`;
    document.body.appendChild(toast);
    lucide.createIcons();

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 2000);
  }

  function logout() {
    window.location.href = '/logout';
  }

  document.addEventListener('DOMContentLoaded', () => init());
})();

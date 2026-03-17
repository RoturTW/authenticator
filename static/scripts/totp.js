window.TOTP = {
  base32Chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',

  base32Decode(str) {
    str = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = '';
    for (let i = 0; i < str.length; i++) {
      const val = this.base32Chars.indexOf(str[i]);
      if (val === -1) continue;
      bits += val.toString(2).padStart(5, '0');
    }

    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    }
    return bytes;
  },

  async generateHMAC(keyBytes, counter, algorithm = 'SHA-1') {
    const counterBytes = new ArrayBuffer(8);
    const view = new DataView(counterBytes);
    view.setUint32(4, counter, false);

    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: algorithm },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, counterBytes);
    return new Uint8Array(signature);
  },

  dynamicTruncation(hmac) {
    const offset = hmac[hmac.length - 1] & 0x0f;
    return ((hmac[offset] & 0x7f) << 24) |
           ((hmac[offset + 1] & 0xff) << 16) |
           ((hmac[offset + 2] & 0xff) << 8) |
           (hmac[offset + 3] & 0xff);
  },

  async generate(secretBase32, digits = 6, algorithm = 'SHA-1', period = 30) {
    const keyBytes = this.base32Decode(secretBase32);
    const counter = Math.floor(Date.now() / 1000 / period);
    const hmac = await this.generateHMAC(keyBytes, counter, algorithm);
    const code = this.dynamicTruncation(hmac) % Math.pow(10, digits);
    return code.toString().padStart(digits, '0');
  },

  getRemainingSeconds(period = 30) {
    return period - (Math.floor(Date.now() / 1000) % period);
  },

  parseOtpAuthUrl(url) {
    try {
      const uri = new URL(url);
      if (uri.protocol !== 'otpauth:') return null;

      const params = new URLSearchParams(uri.search);
      const pathParts = uri.pathname.split('/');
      const type = pathParts[0].replace(':', '');
      
      let issuer = params.get('issuer') || '';
      let name = '';
      
      if (pathParts.length > 1) {
        const label = decodeURIComponent(pathParts.slice(1).join('/'));
        if (label.includes(':')) {
          const parts = label.split(':');
          issuer = issuer || parts[0];
          name = parts.slice(1).join(':');
        } else {
          name = label;
        }
      }

      return {
        secret: params.get('secret'),
        issuer: issuer || 'Unknown',
        name: name || 'Account',
        digits: parseInt(params.get('digits')) || 6,
        algorithm: params.get('algorithm') || 'SHA-1',
        period: parseInt(params.get('period')) || 30
      };
    } catch (e) {
      return null;
    }
  }
};

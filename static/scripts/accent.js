// The accent colour, chosen per person and kept in localStorage. A port of roturPhotos'
// src/accent/accent.ts: accent.css derives every --r-accent-* token from --r-accent-base,
// and this only sets that one colour (and the text colour that sits on it). It runs in
// <head> so the page never paints in the wrong colour first.
const accent = (() => {
  const fallback = '#59d4b4';
  const hex = /^#[0-9a-f]{6}$/i;
  const key = `rotur-accent:authenticator:${document.documentElement.dataset.user || 'signed-out'}`;

  // WCAG relative luminance, 0 (black) to 1 (white).
  function luminance(value) {
    const channel = (i) => {
      const c = parseInt(value.slice(i, i + 2), 16) / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
  }

  function apply(value) {
    const root = document.documentElement;
    root.style.setProperty('--r-accent-base', value);
    root.style.setProperty('--r-on-accent', luminance(value) > 0.18 ? '#120c08' : '#ffffff');
  }

  function saved() {
    try {
      const value = localStorage.getItem(key) || '';
      return hex.test(value) ? value.toLowerCase() : fallback;
    } catch {
      return fallback;
    }
  }

  let current = saved();
  apply(current);

  return {
    fallback,
    // The app's own colour first, then a few that read well on black.
    swatches: [
      { hex: fallback, name: 'Teal' },
      { hex: '#c299cf', name: 'Lilac' },
      { hex: '#8aa2ff', name: 'Periwinkle' },
      { hex: '#56c6e8', name: 'Sky' },
      { hex: '#ffc35a', name: 'Marigold' },
      { hex: '#f7a46b', name: 'Apricot' },
      { hex: '#ff86b4', name: 'Pink' },
    ],
    get current() { return current; },
    set(value) {
      if (!hex.test(value)) return;
      current = value.toLowerCase();
      apply(current);
      try {
        if (current === fallback) localStorage.removeItem(key);
        else localStorage.setItem(key, current);
      } catch {
        // Private browsing: the colour still applies for this visit.
      }
    },
  };
})();

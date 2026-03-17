window.onload = function () {
  const urlParams = new URLSearchParams(window.location.search);
  const tokenFromUrl = urlParams.get('token');

  if (tokenFromUrl) {
    document.cookie = `auth_token=${tokenFromUrl}; path=/; max-age=31536000; SameSite=Lax`;

    fetch("https://api.rotur.dev/me?auth=" + tokenFromUrl)
      .then(res => res.json())
      .then(data => {
        document.cookie = `username=${data.username}; path=/; max-age=31536000; SameSite=Lax`;
        window.location.href = '/';
      });
    return;
  }

  const returnTo = window.location.href.split('?')[0];
  window.location.href = "https://rotur.dev/auth?return_to=".concat(encodeURIComponent(returnTo));
};

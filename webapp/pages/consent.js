// Cookie consent banner + settings modal (pattern from hotelsancho.new CookieConsent.tsx).
// Strictly necessary storage (Clerk session cookies, this consent record) is always on.
// Functional = Google Fonts, which sends the visitor's IP to Google, so it only loads with consent.
(() => {
  const STORAGE_KEY = "cookie-consent";
  const VERSION = "1.0";
  const FONTS_URL =
    "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap";

  const icon = {
    cookie: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5z"/><path d="M8.5 8.5h.01M16 15.5h.01M12 12h.01M11 17h.01M7 14h.01"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z"/><path d="m9 12 2 2 4-4" stroke-linecap="round"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/></svg>',
    close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>',
  };

  const css = `
    .es-cc, .es-cc * { box-sizing: border-box; }
    .es-cc { font-family: 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif; color: #fafafa; }
    .es-cc svg { width: 1em; height: 1em; flex-shrink: 0; }
    .es-cc button { font: inherit; cursor: pointer; }
    .es-cc a { color: #a1a1aa; text-decoration: underline; }
    .es-cc a:hover { color: #34d399; }
    .es-cc-banner {
      position: fixed; left: 0; right: 0; bottom: 0; z-index: 200;
      background: #131316; border-top: 2px solid #10b981;
      box-shadow: 0 -12px 40px rgba(0,0,0,0.5);
    }
    .es-cc-banner-inner { max-width: 1100px; margin: 0 auto; padding: 24px; display: flex; gap: 16px; align-items: flex-start; }
    .es-cc-big { font-size: 1.9rem; color: #10b981; }
    .es-cc-body { flex: 1; }
    .es-cc h3 { font-size: 1.05rem; font-weight: 600; margin: 0 0 6px; }
    .es-cc p { font-size: 0.875rem; line-height: 1.6; color: #a1a1aa; margin: 0; }
    .es-cc-actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px; }
    .es-cc-btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 8px;
      padding: 9px 20px; border-radius: 8px; font-size: 0.85rem; font-weight: 600;
      border: 1px solid transparent; transition: background 0.2s, border-color 0.2s;
    }
    .es-cc-primary { background: #10b981; color: #000; }
    .es-cc-primary:hover { background: #34d399; }
    .es-cc-secondary { background: #3f3f46; color: #fafafa; }
    .es-cc-secondary:hover { background: #52525b; }
    .es-cc-outline { background: transparent; border-color: #27272a; color: #a1a1aa; }
    .es-cc-outline:hover { background: #1a1a1f; color: #fafafa; }
    .es-cc-small { margin-top: 12px; font-size: 0.75rem; }
    .es-cc-x { background: none; border: 0; color: #71717a; font-size: 1.25rem; padding: 2px; }
    .es-cc-x:hover { color: #fafafa; }
    .es-cc-overlay {
      position: fixed; inset: 0; z-index: 200; background: rgba(0,0,0,0.6);
      backdrop-filter: blur(6px); display: flex; align-items: center; justify-content: center; padding: 16px;
    }
    .es-cc-modal {
      background: #131316; border: 1px solid #27272a; border-radius: 16px;
      box-shadow: 0 24px 60px rgba(0,0,0,0.6); width: 100%; max-width: 640px;
      max-height: 90vh; overflow-y: auto; padding: 24px;
    }
    .es-cc-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; }
    .es-cc-head-title { display: flex; align-items: center; gap: 12px; }
    .es-cc h2 { font-size: 1.4rem; font-weight: 700; margin: 0; letter-spacing: -0.02em; }
    .es-cc-cats { display: grid; gap: 14px; margin-top: 20px; }
    .es-cc-cat { border: 1px solid #27272a; border-radius: 12px; padding: 16px; }
    .es-cc-cat-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 6px; }
    .es-cc-cat-title { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 0.95rem; }
    .es-cc-dot { width: 8px; height: 8px; border-radius: 50%; }
    .es-cc-pill { background: rgba(16,185,129,0.15); color: #34d399; padding: 4px 12px; border-radius: 999px; font-size: 0.72rem; font-weight: 600; }
    .es-cc-switch { position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0; }
    .es-cc-switch input { position: absolute; opacity: 0; width: 100%; height: 100%; margin: 0; cursor: pointer; z-index: 1; }
    .es-cc-track { position: absolute; inset: 0; background: #3f3f46; border-radius: 999px; transition: background 0.2s; }
    .es-cc-track::after {
      content: ""; position: absolute; top: 2px; left: 2px; width: 20px; height: 20px;
      background: #fff; border-radius: 50%; transition: transform 0.2s;
    }
    .es-cc-switch input:checked + .es-cc-track { background: #10b981; }
    .es-cc-switch input:checked + .es-cc-track::after { transform: translateX(20px); }
    .es-cc-switch input:focus-visible + .es-cc-track { outline: 2px solid #34d399; outline-offset: 2px; }
    .es-cc-modal .es-cc-actions { margin-top: 28px; }
    .es-cc-modal .es-cc-btn { padding: 11px 20px; }
    .es-cc-center { text-align: center; margin-top: 16px; font-size: 0.85rem; }
    @media (max-width: 640px) {
      .es-cc-banner-inner { padding: 18px 16px; }
      .es-cc-big { display: none; }
      .es-cc-actions { flex-direction: column; }
    }
  `;

  function readConsent() {
    try {
      const data = JSON.parse(localStorage.getItem(STORAGE_KEY));
      return data && data.version === VERSION ? data.preferences : null;
    } catch {
      return null;
    }
  }

  function applyPreferences(prefs) {
    const existing = document.getElementById("es-google-fonts");
    if (prefs.functional && !existing) {
      for (const origin of ["https://fonts.googleapis.com", "https://fonts.gstatic.com"]) {
        const pre = document.createElement("link");
        pre.rel = "preconnect";
        pre.href = origin;
        if (origin.includes("gstatic")) pre.crossOrigin = "";
        document.head.appendChild(pre);
      }
      const link = document.createElement("link");
      link.id = "es-google-fonts";
      link.rel = "stylesheet";
      link.href = FONTS_URL;
      document.head.appendChild(link);
    } else if (!prefs.functional && existing) {
      existing.remove();
    }
  }

  function save(prefs) {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ preferences: prefs, timestamp: new Date().toISOString(), version: VERSION })
    );
    applyPreferences(prefs);
    hide();
  }

  const acceptAll = () => save({ necessary: true, functional: true });
  const acceptNecessary = () => save({ necessary: true, functional: false });

  let root = null;

  function mount(html) {
    hide();
    root = document.createElement("div");
    root.className = "es-cc";
    root.innerHTML = html;
    document.body.appendChild(root);
    root.addEventListener("click", (e) => {
      const action = e.target.closest("[data-cc]")?.dataset.cc;
      if (action === "all") acceptAll();
      else if (action === "necessary") acceptNecessary();
      else if (action === "customize") showSettings();
      else if (action === "close") hide();
      else if (action === "save") save({ necessary: true, functional: root.querySelector("#es-cc-functional").checked });
      else if (e.target.classList.contains("es-cc-overlay")) hide();
    });
  }

  function hide() {
    root?.remove();
    root = null;
  }

  function showBanner() {
    mount(`
      <div class="es-cc-banner" role="region" aria-label="Cookie consent">
        <div class="es-cc-banner-inner">
          <span class="es-cc-big">${icon.cookie}</span>
          <div class="es-cc-body">
            <h3>We use cookies</h3>
            <p>We use strictly necessary cookies to keep you signed in. With your permission we also load
              web fonts from Google Fonts, which shares your IP address with Google. We don't use analytics
              or advertising cookies.</p>
            <div class="es-cc-actions">
              <button class="es-cc-btn es-cc-primary" data-cc="all">${icon.check} Accept all</button>
              <button class="es-cc-btn es-cc-secondary" data-cc="necessary">Necessary only</button>
              <button class="es-cc-btn es-cc-outline" data-cc="customize">${icon.settings} Customize</button>
            </div>
            <div class="es-cc-small"><a href="/cookies">Learn more in our Cookie Policy</a> &middot; <a href="/privacy">Privacy Policy</a></div>
          </div>
          <button class="es-cc-x" data-cc="close" aria-label="Close">${icon.close}</button>
        </div>
      </div>`);
  }

  function showSettings() {
    const prefs = readConsent() || { necessary: true, functional: false };
    mount(`
      <div class="es-cc-overlay">
        <div class="es-cc-modal" role="dialog" aria-modal="true" aria-labelledby="es-cc-title">
          <div class="es-cc-head">
            <div class="es-cc-head-title">
              <span class="es-cc-big">${icon.shield}</span>
              <h2 id="es-cc-title">Cookie Settings</h2>
            </div>
            <button class="es-cc-x" data-cc="close" aria-label="Close">${icon.close}</button>
          </div>
          <p>Choose which cookies and third-party resources we may use. You can change your choice at any
            time from the "Cookie settings" link in the footer.</p>
          <div class="es-cc-cats">
            <div class="es-cc-cat">
              <div class="es-cc-cat-head">
                <div class="es-cc-cat-title"><span class="es-cc-dot" style="background:#ef4444"></span>Strictly necessary</div>
                <span class="es-cc-pill">Always active</span>
              </div>
              <p>Required for sign-in and account security (Clerk session cookies) and to remember this
                choice. The site can't work without them, so they can't be turned off.</p>
            </div>
            <div class="es-cc-cat">
              <div class="es-cc-cat-head">
                <div class="es-cc-cat-title"><span class="es-cc-dot" style="background:#10b981"></span>Functional</div>
                <label class="es-cc-switch">
                  <input type="checkbox" id="es-cc-functional" aria-label="Allow functional cookies" ${prefs.functional ? "checked" : ""}>
                  <span class="es-cc-track"></span>
                </label>
              </div>
              <p>Loads the Inter and JetBrains Mono fonts from Google Fonts. Google receives your IP address
                and browser details. If disabled, your system fonts are used instead.</p>
            </div>
          </div>
          <div class="es-cc-actions">
            <button class="es-cc-btn es-cc-primary" data-cc="save">${icon.check} Save preferences</button>
            <button class="es-cc-btn es-cc-secondary" data-cc="all">Accept all</button>
            <button class="es-cc-btn es-cc-outline" data-cc="necessary">Reject all</button>
          </div>
          <div class="es-cc-center"><a href="/cookies">Learn more about our use of cookies</a></div>
        </div>
      </div>`);
    root.querySelector("#es-cc-functional").focus();
  }

  function init() {
    const style = document.createElement("style");
    style.textContent = css;
    document.head.appendChild(style);

    // Any element with data-cookie-settings reopens the settings (e.g. footer link)
    document.addEventListener("click", (e) => {
      if (e.target.closest("[data-cookie-settings]")) {
        e.preventDefault();
        showSettings();
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && root?.querySelector(".es-cc-overlay")) hide();
    });

    const prefs = readConsent();
    if (prefs) applyPreferences(prefs);
    else setTimeout(showBanner, 1000);
  }

  window.EnvSaveConsent = { open: () => showSettings() };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

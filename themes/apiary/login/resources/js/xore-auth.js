/* APIARY Keycloak login theme -- Xore interaction layer (#103).
 *
 * Progressive enhancement only: every behavior here is additive on top of
 * Keycloak's own login.ftl/webauthn*.ftl markup and scripts. If this file
 * fails to load or throws, the plain inherited Keycloak form (username +
 * password on one page, real submit button) still works exactly as
 * Keycloak ships it -- #104's own acceptance criterion. Nothing here
 * replaces Keycloak's request handling, WebAuthn ceremony, or validation;
 * it only stages the existing fields visually and adds a theme toggle,
 * mirroring the historical production login's interaction (auth-backend
 * commit 3c2779a) without reviving its bespoke WebAuthn fetch endpoints --
 * this reads/writes only Keycloak's own real field IDs.
 *
 * Loaded via theme.properties' `scripts=js/xore-auth.js`, which Keycloak
 * injects as a plain blocking <script> in <head> (base/login/template.ftl)
 * -- not type="module" -- so the pre-paint block below runs synchronously
 * before first paint, same as the historical page's own inline bootstrap.
 * Everything DOM-dependent waits for DOMContentLoaded since <body> does
 * not exist yet when this executes.
 */
(function () {
  "use strict";

  var THEME_KEY = "hp-theme";

  function getStoredTheme() {
    try {
      var t = localStorage.getItem(THEME_KEY);
      return t === "light" || t === "dark" ? t : null;
    } catch (e) {
      return null;
    }
  }

  // ---- Pre-paint theme bootstrap (runs immediately, before body exists) ----
  var stored = getStoredTheme();
  if (stored) {
    document.documentElement.dataset.theme = stored;
  }

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    setupThemeToggle();
    setupStagedLogin();
    setupPasskeyBusyState();
  });

  // ---- Fixed theme toggle (top-right; placement CSS already in login.css) ----
  function setupThemeToggle() {
    if (document.getElementById("theme-toggle")) return; // don't double-inject
    var btn = document.createElement("button");
    btn.type = "button";
    btn.id = "theme-toggle";
    btn.className = "theme-toggle";
    btn.setAttribute("aria-label", "Switch color theme");
    document.body.appendChild(btn);

    function current() {
      return getStoredTheme() || "dark";
    }
    function apply(mode) {
      document.documentElement.dataset.theme = mode;
      try {
        localStorage.setItem(THEME_KEY, mode);
      } catch (e) {}
      btn.setAttribute("title", "Theme: " + mode);
      btn.setAttribute("aria-pressed", mode === "light" ? "true" : "false");
    }
    apply(current());
    btn.addEventListener("click", function () {
      apply(current() === "dark" ? "light" : "dark");
    });
  }

  // ---- Identity-then-credential staging on top of login.ftl's combined
  // username+password form -- Keycloak's default browser flow renders both
  // fields on one page/one submit; this only changes what's visible and
  // when, never what gets submitted or how. Real field IDs (#username,
  // #password) and the form's own onsubmit="login.disabled = true" are
  // Keycloak's, confirmed against the pinned release (keycloak.lock). ----
  function setupStagedLogin() {
    var form = document.getElementById("kc-form-login");
    if (!form) return; // not the combined login page -- nothing to stage
    var userInput = document.getElementById("username");
    var passInput = document.getElementById("password");
    if (!userInput || !passInput) return; // identity-only or password-only step

    var userGroup = userInput.closest(".pf-v5-c-form__group");
    var passGroup = passInput.closest(".pf-v5-c-form__group");
    var submitBtn = form.querySelector('input[type="submit"], button[type="submit"]');
    if (!userGroup || !passGroup || !submitBtn) return;

    // A failed attempt re-renders this same page with an error already
    // attached -- show both fields immediately so the error is visible in
    // context instead of hiding it behind a "Continue" step the user
    // already passed. Checked against the whole form, not just the
    // password group: confirmed live that Keycloak's real login.ftl
    // attaches the shared "Invalid username or password" error to
    // #username (messagesPerField.getFirstError('username','password'),
    // via the username field's own macro call), not #password -- an
    // invalid-credentials retry would otherwise get staged straight back
    // to the identity step, one extra click removed from where the visible
    // error actually is.
    if (form.querySelector('[aria-invalid="true"]')) return;

    var whoLabel = document.createElement("div");
    whoLabel.className = "kc-signing-in-as";
    whoLabel.hidden = true;
    var whoText = document.createElement("span");
    whoText.className = "kc-signing-in-as__who";
    var changeBtn = document.createElement("button");
    changeBtn.type = "button";
    changeBtn.className = "kc-change-username";
    changeBtn.textContent = "change";
    whoLabel.appendChild(document.createTextNode("signing in as "));
    whoLabel.appendChild(whoText);
    whoLabel.appendChild(changeBtn);
    passGroup.parentNode.insertBefore(whoLabel, passGroup);

    var isValueProp = "value" in submitBtn;
    var originalLabel = isValueProp ? submitBtn.value : submitBtn.textContent;
    function setLabel(text) {
      if (isValueProp) submitBtn.value = text;
      else submitBtn.textContent = text;
    }

    function showIdentityStep() {
      passGroup.hidden = true;
      whoLabel.hidden = true;
      userGroup.hidden = false;
      setLabel("Continue");
      submitBtn.dataset.step = "identity";
      userInput.focus();
    }
    function showCredentialStep() {
      whoText.textContent = userInput.value.trim();
      userGroup.hidden = true;
      whoLabel.hidden = false;
      passGroup.hidden = false;
      setLabel(originalLabel);
      submitBtn.dataset.step = "credential";
      passInput.focus();
    }

    changeBtn.addEventListener("click", showIdentityStep);

    form.addEventListener("submit", function (e) {
      if (submitBtn.dataset.step === "identity") {
        e.preventDefault();
        if (!userInput.value.trim()) {
          userInput.focus();
          return;
        }
        showCredentialStep();
      }
      // Credential-step submit: Keycloak's own inline onsubmit handler
      // (login.disabled = true) already runs via the form's own attribute.
    });

    userInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && submitBtn.dataset.step === "identity") {
        e.preventDefault();
        if (userInput.value.trim()) showCredentialStep();
      }
    });

    showIdentityStep();
  }

  // ---- Passkey ceremony busy state -- Keycloak's own webauthnAuthenticate.js
  // /webauthnRegister.js own the actual navigator.credentials call and
  // already attach a { once: true } click listener to these exact IDs
  // (confirmed against the pinned release), so this only adds a visual
  // busy state alongside it -- never replaces or races Keycloak's own
  // handler. ----
  function setupPasskeyBusyState() {
    ["authenticateWebAuthnButton", "registerWebAuthn"].forEach(function (id) {
      var btn = document.getElementById(id);
      if (!btn) return;
      btn.addEventListener("click", function () {
        btn.setAttribute("aria-busy", "true");
        btn.classList.add("kc-busy");
      });
    });
  }
})();

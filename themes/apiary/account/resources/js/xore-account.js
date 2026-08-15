/* APIARY Keycloak account console theme -- accessibility patch (#113).
 *
 * Progressive enhancement only, same contract as the login theme's own
 * xore-auth.js: if this fails to load or throws, the inherited keycloak.v3
 * Account Console still works exactly as Keycloak ships it.
 *
 * keycloak.v3 renders icon-only "more actions" kebab buttons
 * (`pf-v5-c-menu-toggle pf-m-plain`, e.g. the masthead's own
 * data-testid="options-kebab-toggle") with no aria-label, no inner text,
 * and no aria-labelledby -- a critical WCAG button-name violation
 * (axe-core, confirmed live at mobile-390/iphone-393 widths, where the
 * masthead's own user-menu options collapse into exactly this kebab and it
 * becomes the only way to reach them). The same unlabeled-kebab pattern
 * also shows up per-credential-row (e.g. Signing in's OTP row, #113) below
 * PatternFly's `lg` breakpoint -- targeting the class rather than one
 * specific data-testid catches every instance instead of only the one
 * axe happened to have visited. This is compiled upstream PatternFly/React
 * markup this repo doesn't own the source of, so it can't be fixed in a
 * template -- only patched after render.
 *
 * Loaded via theme.properties' `scripts=js/xore-account.js`. The Account
 * Console is a client-rendered SPA: the target button doesn't exist at
 * script-execution time, and gets destroyed/recreated by React on every
 * resize-driven toolbar re-layout and on every client-side route change --
 * a one-shot DOMContentLoaded label would miss all of that, so this
 * watches for it continuously instead.
 */
(function () {
  "use strict";

  var KEBAB_SELECTOR = "button.pf-v5-c-menu-toggle.pf-m-plain";
  var LABEL = "More options";

  function labelKebabs() {
    var kebabs = document.querySelectorAll(KEBAB_SELECTOR);
    for (var i = 0; i < kebabs.length; i++) {
      if (!kebabs[i].hasAttribute("aria-label")) {
        kebabs[i].setAttribute("aria-label", LABEL);
      }
    }
  }

  function start() {
    labelKebabs();
    new MutationObserver(labelKebabs).observe(document.body, { childList: true, subtree: true });
  }

  if (document.body) {
    start();
  } else {
    document.addEventListener("DOMContentLoaded", start);
  }
})();

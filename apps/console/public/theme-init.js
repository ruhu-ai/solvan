/* Theme before paint. preferences.ts is the owner of this decision, but it
   cannot run until the module bundle parses, and a light first frame in front
   of someone working in dark is a flash they did not ask for. This reads the
   same key and applies the same rule, then gets out of the way. It lives in an
   external file rather than inline because the deployed content policy is
   script-src 'self': an inline script is blocked, and the policy stays
   hash-free. Keep the storage key and the SYSTEM/LIGHT/DARK values in step
   with preferences.ts; a disagreement here shows up as a flicker, not an
   error. */
(function () {
  try {
    var raw = window.localStorage.getItem("solvan.console.preferences.v1");
    var pref = raw ? JSON.parse(raw).preferences.theme : "SYSTEM";
    var dark =
      pref === "DARK" ||
      (pref !== "LIGHT" &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
  } catch (error) {
    /* Storage blocked or the record is malformed: fall through to the system
       default, which the stylesheet and preferences.ts both honour. */
  }
})();

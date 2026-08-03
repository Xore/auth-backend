// Tailwind config for the standalone CLI build of ui/tailwind.min.css.
// Rebuild with:  docker compose --profile build run --rm tailwind-build
// (or run the pinned tools/tailwindcss binary directly — same flags).
module.exports = {
  content: ["ui/login.html", "ui/verify.html"],
  // Colors and fonts reference Xore/theme's theme.css custom properties
  // (vendored at ui/theme.css) instead of hardcoded hex, so light/dark mode
  // and any future theme update apply here automatically instead of
  // silently drifting from the shared design system.
  theme: {
    extend: {
      colors: {
        bg:       'var(--app-bg)',      // page background
        surface:  'var(--surface-1)',   // card / button background
        border:   'var(--border-subtle)', // borders, dividers
        muted:    'var(--text-muted)',  // secondary text, labels, placeholders
        primary:  'var(--accent)',      // terracotta accent — focus rings, icons
        primaryh: 'var(--accent-hover)',
        inputbg:  'var(--surface-0)',   // text input fill
      },
      fontFamily: {
        serif: ['var(--font-display)'],
        sans:  ['system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
}

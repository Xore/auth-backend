// Tailwind config for the standalone CLI build of ui/tailwind.min.css.
// Rebuild with:  docker compose --profile build run --rm tailwind-build
// (or run the pinned tools/tailwindcss binary directly — same flags).
module.exports = {
  content: ["ui/login.html", "ui/verify.html"],
  theme: {
    extend: {
      colors: {
        bg:       '#1a1a1a', // page background
        surface:  '#242424', // card / button background
        border:   '#2e2e2e', // borders, dividers
        muted:    '#8a8a8a', // secondary text, labels, placeholders
        primary:  '#d4764e', // terracotta accent — focus rings, icons
        primaryh: '#c4673f',
        inputbg:  '#1f1f1f', // text input fill
      },
      fontFamily: {
        serif: ['Georgia', 'Cambria', 'serif'],
        sans:  ['system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
}

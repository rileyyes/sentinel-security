export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: { 900: "#0f1419", 800: "#171e26", 700: "#1f2833", 600: "#2a3440" },
        accent: { DEFAULT: "#4f8cff", dim: "#2a5bb0" },
        warn: "#e3b341", danger: "#ff7b72", info: "#79c0ff", muted: "#8b949e",
      },
      fontFamily: { mono: ["JetBrains Mono", "ui-monospace", "monospace"] },
    },
  },
  plugins: [],
};

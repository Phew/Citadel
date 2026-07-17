/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // App chrome palette — neutral; no security-color claims
        shell: {
          bg: "#0f1115",
          panel: "#161a22",
          border: "#2a3140",
          muted: "#8b93a7",
          text: "#e8ecf4",
          accent: "#6b8cff",
          warn: "#e6a23c",
          danger: "#e05c5c",
        },
      },
      fontFamily: {
        sans: [
          "Segoe UI",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "sans-serif",
        ],
        mono: ["ui-monospace", "Cascadia Code", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};

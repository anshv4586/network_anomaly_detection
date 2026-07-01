/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          black: "#030712",
          dark: "#0b0f19",
          card: "#111827",
          border: "#1f2937",
          cyan: "#06b6d4",
          green: "#10b981",
          red: "#ef4444",
          yellow: "#f59e0b",
          blue: "#3b82f6"
        }
      },
      boxShadow: {
        'glow-cyan': '0 0 15px rgba(6, 182, 212, 0.25)',
        'glow-green': '0 0 15px rgba(16, 185, 129, 0.25)',
        'glow-red': '0 0 15px rgba(239, 68, 68, 0.25)',
        'glow-yellow': '0 0 15px rgba(245, 158, 11, 0.25)',
      }
    },
  },
  plugins: [],
}

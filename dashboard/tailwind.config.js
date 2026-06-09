/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: "#0f172a",
        card: "#1e293b",
        border: "#334155",
        cyan: "#06b6d4",
        critical: "#ef4444",
        high: "#f59e0b",
        medium: "#8b5cf6",
        low: "#10b981",
      }
    },
  },
  plugins: [],
}

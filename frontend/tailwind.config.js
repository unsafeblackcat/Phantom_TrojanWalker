/** @type {import('tailwindcss').Config} */
// Refactor: name content paths to improve readability.
const contentPaths = [
  "./index.html",
  "./src/**/*.{js,ts,jsx,tsx}",
]

export default {
  content: contentPaths,
  theme: {
    extend: {},
  },
  plugins: [],
}

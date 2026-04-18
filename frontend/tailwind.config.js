/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        brand:  '#30c074',
        canvas: '#0d1117',
        card:   '#161b22',
        rim:    '#30363d',
        dim:    '#8b949e',
        lit:    '#e6edf3',
        body:   '#c9d1d9',
        hover:  '#1c2128',
      },
      fontFamily: {
        sans: ["'Segoe UI'", 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  plugins: [],
};

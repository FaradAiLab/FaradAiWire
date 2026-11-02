/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: 'var(--bg-canvas)',
        surface: 'var(--bg-surface)',
        'surface-elevated': 'var(--bg-surface-elevated)',
        'surface-muted': 'var(--bg-surface-muted)',
        subtle: 'var(--border-subtle)',
        'border-strong': 'var(--border-strong)',
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)',
        muted: 'var(--text-muted)',
        accent: {
          DEFAULT: 'var(--accent-primary)',
          hover: 'var(--accent-primary-hover)',
          primary: 'var(--accent-primary)',
          'primary-hover': 'var(--accent-primary-hover)',
        },
        dark: {
          bg: '#0b0f17',
          card: 'rgba(17, 24, 39, 0.75)',
          surface: 'rgba(31, 41, 55, 0.5)',
          border: 'rgba(255, 255, 255, 0.08)',
        },
        neon: {
          cyan: '#06b6d4',
          green: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e',
          indigo: '#6366f1',
        },
      },
      fontFamily: {
        sans: ['Outfit', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}

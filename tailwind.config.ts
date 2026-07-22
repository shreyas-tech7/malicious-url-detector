import type { Config } from "tailwindcss";
import defaultTheme from "tailwindcss/defaultTheme";

/**
 * Tokens resolve to `rgb(var(--token) / <alpha-value>)` rather than to a bare
 * `var(--token)`. Tailwind has to be able to substitute the alpha channel, and
 * it cannot see inside an opaque var reference — with `"var(--surface-1)"`,
 * `bg-surface-1` works but `bg-surface-1/60` compiles to nothing at all.
 */
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      /*
       * layout.tsx loads both Geist faces and exposes them as CSS variables,
       * but nothing consumed them until this block existed — the page rendered
       * in the browser default serif while still paying 134KB to download the
       * fonts.
       *
       * The sans/mono split is semantic here, not decorative: mono marks
       * anything the model produced or was given (URLs, scores, feature
       * names), sans marks editorial prose. Reading the page, you can tell
       * machine output from authored text by its typeface alone.
       */
      fontFamily: {
        sans: ["var(--font-geist-sans)", ...defaultTheme.fontFamily.sans],
        mono: ["var(--font-geist-mono)", ...defaultTheme.fontFamily.mono],
      },
      colors: {
        surface: {
          0: token("surface-0"),
          1: token("surface-1"),
          2: token("surface-2"),
        },
        line: {
          DEFAULT: token("line"),
          strong: token("line-strong"),
        },
        fg: {
          strong: token("fg-strong"),
          DEFAULT: token("fg"),
          muted: token("fg-muted"),
          faint: token("fg-faint"),
        },
      },
      boxShadow: {
        card: "var(--shadow-card)",
        raised: "var(--shadow-raised)",
      },
      animation: {
        "rise-in": "rise-in 420ms var(--ease-settle) both",
        "sweep-x": "sweep-x 620ms var(--ease-settle) both",
      },
      letterSpacing: {
        display: "-0.03em",
      },
    },
  },
  plugins: [],
};
export default config;

import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypeScript from "eslint-config-next/typescript";

/*
 * Flat config, required by ESLint 10 — the previous `.eslintrc.json` was in a
 * format ESLint 10 no longer reads, and `npm run lint` invoked `next lint`,
 * which Next 16 removed. Between the two, this project had no working linter.
 *
 * `eslint-config-next/core-web-vitals` already re-exports `next/typescript`,
 * so it carries the Next rules and the TS parser on its own.
 * `eslint-config-next/typescript` is layered on top for
 * typescript-eslint's recommended set, which the Next config does not include.
 */

const unwrap = (mod) => (Array.isArray(mod) ? mod : mod.default);

/** @type {import('eslint').Linter.Config[]} */
const config = [
  {
    // Build output, vendored code, and the Python side of the project. ESLint
    // has nothing useful to say about any of it, and `.next` alone is large
    // enough to dominate a run.
    ignores: [
      ".next/**",
      "node_modules/**",
      ".vercel/**",
      "ml/**",
      "api/**",
      "supabase/**",
      "next-env.d.ts",
    ],
  },
  ...unwrap(nextCoreWebVitals),
  ...unwrap(nextTypeScript),
  {
    name: "project/overrides",
    files: ["**/*.{ts,tsx,mjs}"],
    /*
     * Pinned, not "detect".
     *
     * eslint-config-next ships eslint-plugin-react 7.37.5, whose version
     * sniffing calls `context.getFilename()` — removed in ESLint 10, so every
     * run crashes with "contextOrFilename.getFilename is not a function"
     * before reporting anything. An explicit version skips that code path
     * entirely. Keep it in step with the `react` dependency in package.json.
     */
    settings: { react: { version: "19.2" } },
    rules: {
      /*
       * The codebase already treats unused bindings as a defect rather than a
       * warning; this makes the linter agree. `_`-prefixed names stay legal so
       * a deliberately ignored parameter can still be named.
       */
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      // A bare `catch {}` is used deliberately in the fetch paths, where the
      // error object carries nothing the user can act on.
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
];

export default config;

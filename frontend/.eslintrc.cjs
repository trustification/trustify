/* eslint-env node */

module.exports = {
  root: true,

  env: {
    browser: true,
    es2020: true,
    jest: true,
  },

  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaFeatures: {
      jsx: true,
    },
    ecmaVersion: 2020, // keep in sync with tsconfig.json
    sourceType: "module",
  },

  // eslint-disable-next-line prettier/prettier
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react/recommended",
    "prettier",
  ],

  // eslint-disable-next-line prettier/prettier
  plugins: [
    "prettier",
    "unused-imports", // or eslint-plugin-import?
    "@typescript-eslint",
    "react",
    "react-hooks",
    "@tanstack/query",
  ],

  // NOTE: Tweak the rules as needed when bulk fixes get merged
  rules: {
    // TODO: set to "error" when prettier v2 to v3 style changes are fixed
    "prettier/prettier": ["warn"],

    // TODO: set to "error" when all resolved, but keep the `argsIgnorePattern`
    "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],

    // TODO: each one of these can be removed or set to "error" when they're all resolved
    "unused-imports/no-unused-imports": ["warn"],
    "@typescript-eslint/ban-types": "warn",
    "@typescript-eslint/no-explicit-any": "warn",
    "react/jsx-key": "warn",
    "react-hooks/rules-of-hooks": "warn",
    "react-hooks/exhaustive-deps": "warn",
    "no-extra-boolean-cast": "warn",
    "prefer-const": "warn",

    // Allow the "cy-data" property for trustification-ui-test (but should really be "data-cy" w/o this rule)
    "react/no-unknown-property": ["error", { ignore: ["cy-data"] }],

    "@tanstack/query/exhaustive-deps": "error",
    "@tanstack/query/prefer-query-object-syntax": "error",
  },

  settings: {
    react: { version: "detect" },
  },

  ignorePatterns: [
    // don't ignore dot files so config files get linted
    "!.*.js",
    "!.*.cjs",
    "!.*.mjs",

    // take the place of `.eslintignore`
    "dist/",
    "generated/",
    "node_modules/",
  ],

  // this is a hack to make sure eslint will look at all of the file extensions we
  // care about without having to put it on the command line
  overrides: [
    {
      files: [
        "**/*.js",
        "**/*.jsx",
        "**/*.cjs",
        "**/*.mjs",
        "**/*.ts",
        "**/*.tsx",
      ],
    },
  ],
};

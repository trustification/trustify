/* eslint-env node */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import util from "node:util";

import copy from "rollup-plugin-copy";
import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import virtual from "@rollup/plugin-virtual";
import ejs from "ejs";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const pathTo = (...relativePath) => path.resolve(__dirname, ...relativePath);

const baseBrandingPath = process.env.BRANDING ?? "./branding";
const brandingPath = pathTo("../", baseBrandingPath);
const jsonStrings = JSON.parse(
  readFileSync(path.resolve(brandingPath, "./strings.json"), "utf8")
);
const stringModule = ejs.render(
  `
  export const strings = ${util.inspect(jsonStrings)};
  export default strings;
`,
  {
    brandingRoot: "branding",
  }
);

console.log("Using branding assets from:", brandingPath);

const config = {
  input: "src/index.ts",

  output: [
    {
      file: "dist/index.mjs",
      format: "esm",
      sourcemap: true,
    },
    {
      file: "dist/index.cjs",
      format: "cjs",
      sourcemap: true,
    },
  ],

  watch: {
    clearScreen: false,
  },

  plugins: [
    copy({
      targets: [{ src: `${brandingPath}/**/*`, dest: "dist/branding" }],
    }),
    nodeResolve(),
    typescript(),
    virtual({
      "@branding/strings.json": stringModule,
    }),
  ],
};

export default config;

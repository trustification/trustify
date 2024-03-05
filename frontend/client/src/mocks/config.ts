import { ENV } from "@app/env";

// Samples of what mock string to parse:
// MOCK=
// MOCK=off
// MOCK=+pass
// MOCK=full
// MOCK=-full
// MOCK=stub
// MOCK=stub=*
// MOCK=stub=*.pass
// MOCK=stub=1,2,3.pass
// MOCK=stub=1,2,3.+pass
// MOCK=stub=1,2,3.-pass

/**
 * Parse the provided MOCK configuration string and return a configuration object.
 */
export function parseMock(str?: string): {
  enabled: boolean;
  passthrough: boolean;
  stub: boolean | "*" | string[];
  full: boolean;
} {
  const regexOff = /^(off)?$/;
  const regexPassthrough = /^([+-]?)pass(through)?$/;
  const regexFull = /^([+-]?)full$/;
  const regexStub = /^stub(=\*|=([a-z0-9\-_]+(\s*,\s*[a-z0-9\-_]+)*))?$/;

  let off = !str;
  let passthrough = false;
  let full = false;
  let stub: boolean | "*" | string[] = false;

  str
    ?.toLowerCase()
    .split(".")
    .map((p) => p.trim())
    .forEach((part) => {
      if (part.match(regexOff)) {
        off = true;
      }

      const matchPassthrough = part.match(regexPassthrough);
      if (matchPassthrough) {
        passthrough =
          matchPassthrough[1].length === 0 || matchPassthrough[1] === "+";
      }

      const matchFull = part.match(regexFull);
      if (matchFull) {
        full = matchFull[1].length === 0 || matchFull[1] === "+";
      }

      const matchStub = part.match(regexStub);
      if (matchStub) {
        if (!matchStub[1] || matchStub[1] === "" || matchStub[1] === "=*") {
          stub = "*";
        } else {
          stub = matchStub[2].split(",").map((s) => s.trim());
        }
      }
    });

  return {
    passthrough,
    stub,
    full,
    enabled: !off && (passthrough || full || !!stub),
  };
}

export const config = Object.freeze(parseMock(ENV.MOCK));
if (ENV.NODE_ENV === "development") {
  console.info("MOCK configuration: ", config);
}

export default config;

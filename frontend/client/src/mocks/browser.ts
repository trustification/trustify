import { type RestHandler, setupWorker, rest } from "msw";

import config from "./config";
import stubNewWork from "./stub-new-work";

/**
 * Handler to catch unhandled traffic to `/hub/*`, log it, and pass it through to the
 * server to handle.  This is useful to see traffic, in the console logs, that is not
 * being mocked elsewhere.
 */
const passthroughHandler: RestHandler = rest.all("/hub/*", (req) => {
  console.log(
    "%cmsw passthrough%c \u{1fa83} %s",
    "font-weight: bold",
    "font-weight: normal",
    req.url
  );
  return req.passthrough();
});

const handlers = [
  // TODO: Add handlers for a FULL hub mock data set
  ...stubNewWork,
  config.passthrough && passthroughHandler,
].filter(Boolean);

/**
 * A setup MSW browser service worker using the handlers configured in the MOCK env var.
 */
export const worker = setupWorker(...handlers);

export { config } from "./config";

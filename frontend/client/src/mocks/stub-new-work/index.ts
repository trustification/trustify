import { type RestHandler } from "msw";
import { config } from "../config";
import advisories from "./advisories";

const enableMe = (me: string) =>
  config.stub === "*" ||
  (Array.isArray(config.stub) ? (config.stub as string[]).includes(me) : false);

/**
 * Return the stub-new-work handlers that are enabled by config.
 */
const enabledStubs: RestHandler[] = [
  ...(enableMe("advisories") ? advisories : []),
].filter(Boolean);

export default enabledStubs;

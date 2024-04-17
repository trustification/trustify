import { type RestHandler } from "msw";
import { config } from "../config";
import advisories from "./advisories";
import cves from "./cves";
import packages from "./packages";
import sboms from "./sboms";

const enableMe = (me: string) =>
  config.stub === "*" ||
  (Array.isArray(config.stub) ? (config.stub as string[]).includes(me) : false);

/**
 * Return the stub-new-work handlers that are enabled by config.
 */
const enabledStubs: RestHandler[] = [
  ...(enableMe("advisories") ? advisories : []),
  ...(enableMe("cves") ? cves : []),
  ...(enableMe("packages") ? packages : []),
  ...(enableMe("sboms") ? sboms : []),
].filter(Boolean);

export default enabledStubs;

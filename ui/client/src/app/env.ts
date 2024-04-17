import { decodeEnv, buildTrustificationEnv } from "@trustify-ui/common";

export const ENV = buildTrustificationEnv(decodeEnv(window._env));

export default ENV;

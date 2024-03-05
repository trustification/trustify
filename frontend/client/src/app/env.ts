import { decodeEnv, buildTrustificationEnv } from "@trustification-ui/common";

export const ENV = buildTrustificationEnv(decodeEnv(window._env));

export default ENV;

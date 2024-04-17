import { AnalyticsBrowserSettings } from "@segment/analytics-next";
import { ENV } from "./env";

export const analyticsSettings: AnalyticsBrowserSettings = {
  writeKey: ENV.ANALYTICS_WRITE_KEY || "",
};

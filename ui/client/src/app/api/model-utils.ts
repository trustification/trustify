import {
  global_palette_purple_400 as criticalColor,
  global_danger_color_100 as importantColor,
  global_info_color_100 as lowColor,
  global_warning_color_100 as moderateColor,
} from "@patternfly/react-tokens";

import { ProgressProps } from "@patternfly/react-core";

import { Severity } from "./models";

type ListType = {
  [key in Severity]: {
    name: string;
    shieldIconColor: { name: string; value: string; var: string };
    progressProps: Pick<ProgressProps, "variant">;
  };
};

export const severityList: ListType = {
  low: {
    name: "Low",
    shieldIconColor: lowColor,
    progressProps: { variant: undefined },
  },
  moderate: {
    name: "Moderate",
    shieldIconColor: moderateColor,
    progressProps: { variant: "warning" },
  },
  important: {
    name: "Important",
    shieldIconColor: importantColor,
    progressProps: { variant: "danger" },
  },
  critical: {
    name: "Critical",
    shieldIconColor: criticalColor,
    progressProps: { variant: "danger" },
  },
};

const getSeverityPriority = (val: Severity) => {
  switch (val) {
    case "low":
      return 1;
    case "moderate":
      return 2;
    case "important":
      return 3;
    case "critical":
      return 4;
    default:
      return 0;
  }
};

export function compareBySeverityFn<T>(
  severityExtractor: (elem: T) => Severity
) {
  return (a: T, b: T) => {
    return (
      getSeverityPriority(severityExtractor(a)) -
      getSeverityPriority(severityExtractor(b))
    );
  };
}

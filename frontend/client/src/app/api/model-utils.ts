import {
  global_palette_purple_400 as criticalColor,
  global_danger_color_100 as importantColor,
  global_info_color_100 as lowColor,
  global_warning_color_100 as moderateColor,
} from "@patternfly/react-tokens";

import { Severity } from "./models";
import { ProgressProps } from "@patternfly/react-core";

type ListType = {
  [key in Severity]: {
    shieldIconColor: { name: string; value: string; var: string };
    progressProps: Pick<ProgressProps, "variant">;
  };
};

export const severityList: ListType = {
  low: {
    shieldIconColor: lowColor,
    progressProps: { variant: undefined },
  },
  moderate: {
    shieldIconColor: moderateColor,
    progressProps: { variant: "warning" },
  },
  important: {
    shieldIconColor: importantColor,
    progressProps: { variant: "danger" },
  },
  critical: {
    shieldIconColor: criticalColor,
    progressProps: { variant: "danger" },
  },
};

export const severityFromNumber = (score: number): Severity => {
  if (score >= 9.0) {
    return "critical";
  } else if (score >= 7.0) {
    return "important";
  } else if (score >= 4.0) {
    return "moderate";
  } else {
    return "low";
  }
};

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

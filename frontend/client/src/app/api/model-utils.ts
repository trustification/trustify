import {
  global_palette_purple_400 as criticalColor,
  global_danger_color_100 as importantColor,
  global_info_color_100 as lowColor,
  global_warning_color_100 as moderateColor,
} from "@patternfly/react-tokens";

import { Severity } from "./models";

type ListType = {
  [key in Severity]: {
    color: { name: string; value: string; var: string };
  };
};

export const severityList: ListType = {
  low: {
    color: lowColor,
  },
  moderate: {
    color: moderateColor,
  },
  important: {
    color: importantColor,
  },
  critical: {
    color: criticalColor,
  },
};

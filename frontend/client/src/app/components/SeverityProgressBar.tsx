import React from "react";

import { Progress } from "@patternfly/react-core";

import { severityFromNumber, severityList } from "@app/api/model-utils";

interface SeverityRendererProps {
  value: number;
  showLabel?: boolean;
}

export const SeverityProgressBar: React.FC<SeverityRendererProps> = ({
  value,
}) => {
  const severityType = severityFromNumber(value);
  const severityProps = severityList[severityType];

  return (
    <>
      <Progress
        aria-labelledby="severity"
        size="sm"
        max={10}
        value={value}
        label={`${value}/10`}
        {...severityProps.progressProps}
      />
    </>
  );
};

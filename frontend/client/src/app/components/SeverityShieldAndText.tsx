import React from "react";

import { Flex, FlexItem } from "@patternfly/react-core";
import ShieldIcon from "@patternfly/react-icons/dist/esm/icons/shield-alt-icon";

import { severityFromNumber, severityList } from "@app/api/model-utils";
import { Severity } from "@app/api/models";

interface SeverityShieldAndTextProps {
  value: Severity | number;
  showLabel?: boolean;
}

export const SeverityShieldAndText: React.FC<SeverityShieldAndTextProps> = ({
  value,
  showLabel,
}) => {
  let severity: Severity;
  if (typeof value === "number") {
    severity = severityFromNumber(value);
  } else {
    severity = value;
  }

  const severityProps = severityList[severity];

  return (
    <>
      <Flex
        spaceItems={{ default: "spaceItemsXs" }}
        alignItems={{ default: "alignItemsCenter" }}
        flexWrap={{ default: "nowrap" }}
        style={{ whiteSpace: "nowrap" }}
      >
        <FlexItem>
          <ShieldIcon color={severityProps.shieldIconColor.value} />
        </FlexItem>
        {showLabel && (
          <FlexItem>
            {severity.charAt(0).toUpperCase() + severity.slice(1)}
          </FlexItem>
        )}
      </Flex>
    </>
  );
};

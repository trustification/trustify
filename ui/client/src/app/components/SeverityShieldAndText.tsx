import React from "react";

import { Flex, FlexItem } from "@patternfly/react-core";
import ShieldIcon from "@patternfly/react-icons/dist/esm/icons/shield-alt-icon";

import { severityList } from "@app/api/model-utils";
import { Severity } from "@app/api/models";

interface SeverityShieldAndTextProps {
  value: Severity;
  hideLabel?: boolean;
}

export const SeverityShieldAndText: React.FC<SeverityShieldAndTextProps> = ({
  value,
  hideLabel,
}) => {
  const severityProps = severityList[value];

  return (
    <Flex
      spaceItems={{ default: "spaceItemsXs" }}
      alignItems={{ default: "alignItemsCenter" }}
      flexWrap={{ default: "nowrap" }}
      style={{ whiteSpace: "nowrap" }}
    >
      <FlexItem>
        <ShieldIcon color={severityProps.shieldIconColor.value} />
      </FlexItem>
      {!hideLabel && (
        <FlexItem>{value.charAt(0).toUpperCase() + value.slice(1)}</FlexItem>
      )}
    </Flex>
  );
};

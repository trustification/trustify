import React from "react";

import { Divider, Flex, FlexItem } from "@patternfly/react-core";

import { Severity } from "@app/api/models";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";

interface VulnerabilitiesCountProps {
  severities: { [key in Severity]: number };
}

export const VulnerabilitiesCount: React.FC<VulnerabilitiesCountProps> = ({
  severities,
}) => {
  const total = Object.entries(severities).reduce(
    (prev, [_severity, count]) => {
      return prev + count;
    },
    0
  );

  return (
    <Flex
      spaceItems={{ default: "spaceItemsSm" }}
      alignItems={{ default: "alignItemsCenter" }}
      flexWrap={{ default: "nowrap" }}
      style={{ whiteSpace: "nowrap" }}
    >
      <FlexItem>{total}</FlexItem>
      <Divider orientation={{ default: "vertical" }} />
      <FlexItem>
        <Flex>
          {Object.entries(severities).map(([severity, count], index) => (
            <FlexItem key={index} spacer={{ default: "spacerXs" }}>
              <Flex
                spaceItems={{ default: "spaceItemsXs" }}
                alignItems={{ default: "alignItemsCenter" }}
                flexWrap={{ default: "nowrap" }}
                style={{ whiteSpace: "nowrap" }}
              >
                <FlexItem>
                  <SeverityShieldAndText
                    value={severity as Severity}
                    hideLabel
                  />
                </FlexItem>
                <FlexItem>{count}</FlexItem>
              </Flex>
            </FlexItem>
          ))}
        </Flex>
      </FlexItem>
    </Flex>
  );
};

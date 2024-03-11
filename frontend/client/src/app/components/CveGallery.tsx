import React from "react";

import { Divider, Flex, FlexItem } from "@patternfly/react-core";

import { compareBySeverityFn } from "@app/api/model-utils";
import { Severity } from "@app/api/models";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";

interface CVEGalleryProps {
  severities: { [key in Severity]: number };
}

export const CveGallery: React.FC<CVEGalleryProps> = ({ severities }) => {
  const severityCount = Object.values(severities).reduce((prev, acc) => {
    return prev + acc;
  }, 0);

  return (
    <Flex
      spaceItems={{ default: "spaceItemsSm" }}
      alignItems={{ default: "alignItemsCenter" }}
      flexWrap={{ default: "nowrap" }}
      style={{ whiteSpace: "nowrap" }}
    >
      <FlexItem>{severityCount}</FlexItem>
      <Divider orientation={{ default: "vertical" }} />
      <FlexItem>
        <Flex>
          {Object.entries(severities)
            .filter(([_severity, count]) => count > 0)
            .sort(
              compareBySeverityFn(([severity, _count]) => severity as Severity)
            )
            .reverse()
            .map(([severity, count], index) => (
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

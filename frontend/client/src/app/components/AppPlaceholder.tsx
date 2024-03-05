import React from "react";
import { Bullseye, Spinner } from "@patternfly/react-core";

export const AppPlaceholder: React.FC = () => {
  return (
    <Bullseye>
      <div className="pf-v5-u-display-flex pf-v5-u-flex-direction-column">
        <div>
          <Spinner />
        </div>
        <div className="pf-v5-c-content">
          <h3>Loading...</h3>
        </div>
      </div>
    </Bullseye>
  );
};

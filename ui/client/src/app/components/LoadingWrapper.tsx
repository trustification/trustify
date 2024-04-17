import React from "react";
import ErrorState from "@patternfly/react-component-groups/dist/esm/ErrorState";
import { Bullseye, Spinner } from "@patternfly/react-core";

export const LoadingWrapper = (props: {
  isFetching: boolean;
  fetchError?: Error;
  children: React.ReactNode;
}) => {
  if (props.isFetching) {
    return (
      <Bullseye>
        <Spinner />
      </Bullseye>
    );
  } else if (props.fetchError) {
    return <ErrorState errorTitle="Error" />;
  } else {
    return props.children;
  }
};

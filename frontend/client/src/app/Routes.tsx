import React, { Suspense, lazy } from "react";
import { useRoutes } from "react-router-dom";

import { Bullseye, Spinner } from "@patternfly/react-core";

const Home = lazy(() => import("./pages/home"));

export const AppRoutes = () => {
  const allRoutes = useRoutes([{ path: "/", element: <Home /> }]);

  return (
    <Suspense
      fallback={
        <Bullseye>
          <Spinner />
        </Bullseye>
      }
    >
      {allRoutes}
    </Suspense>
  );
};

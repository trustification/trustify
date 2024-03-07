import React, { Suspense, lazy } from "react";
import { useRoutes } from "react-router-dom";

import { Bullseye, Spinner } from "@patternfly/react-core";

const Home = lazy(() => import("./pages/home"));
const AdvisoryList = lazy(() => import("./pages/advisory-list"));

export const AppRoutes = () => {
  const allRoutes = useRoutes([
    { path: "/", element: <Home /> },
    { path: "/advisories", element: <AdvisoryList /> },
  ]);

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

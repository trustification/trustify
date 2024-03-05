import "./App.css";
import React from "react";
import { BrowserRouter as Router } from "react-router-dom";

import { DefaultLayout } from "./layout";
import { AppRoutes } from "./Routes";
import { NotificationsProvider } from "./components/NotificationsContext";
import { AnalyticsProvider } from "./components/AnalyticsProvider";

import "@patternfly/patternfly/patternfly.css";
import "@patternfly/patternfly/patternfly-addons.css";

const App: React.FC = () => {
  return (
    <Router>
      <AnalyticsProvider>
        <NotificationsProvider>
          <DefaultLayout>
            <AppRoutes />
          </DefaultLayout>
        </NotificationsProvider>
      </AnalyticsProvider>
    </Router>
  );
};

export default App;

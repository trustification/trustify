import React from "react";

import { Page } from "@patternfly/react-core";

import { HeaderApp } from "./header";
import { SidebarApp } from "./sidebar";
import { Notifications } from "@app/components/Notifications";
import { PageContentWithDrawerProvider } from "@app/components/PageDrawerContext";

interface DefaultLayoutProps {
  children?: React.ReactNode;
}

export const DefaultLayout: React.FC<DefaultLayoutProps> = ({ children }) => {
  return (
    <Page header={<HeaderApp />} sidebar={<SidebarApp />} isManagedSidebar>
      <PageContentWithDrawerProvider>
        {children}
        <Notifications />
      </PageContentWithDrawerProvider>
    </Page>
  );
};

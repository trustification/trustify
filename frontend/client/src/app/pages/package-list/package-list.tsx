import React from "react";

import {
  PageSection,
  PageSectionVariants,
  Text,
  TextContent,
  ToolbarContent,
} from "@patternfly/react-core";

import { usePackageList } from "./usePackageList";

export const PackageList: React.FC = () => {
  const { tableProps, table } = usePackageList();

  const {
    components: { Toolbar, FilterToolbar, PaginationToolbarItem, Pagination },
  } = tableProps;

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <TextContent>
          <Text component="h1">Packages</Text>
        </TextContent>
      </PageSection>
      <PageSection>
        <div
          style={{
            backgroundColor: "var(--pf-v5-global--BackgroundColor--100)",
          }}
        >
          <Toolbar>
            <ToolbarContent>
              <FilterToolbar
                id="package-toolbar"
                {...{ showFiltersSideBySide: true }}
              />
              <PaginationToolbarItem>
                <Pagination
                  variant="top"
                  isCompact
                  widgetId="package-pagination-top"
                />
              </PaginationToolbarItem>
            </ToolbarContent>
          </Toolbar>
          {table}
        </div>
      </PageSection>
    </>
  );
};

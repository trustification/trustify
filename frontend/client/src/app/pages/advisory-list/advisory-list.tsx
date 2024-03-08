import React from "react";

import {
  PageSection,
  PageSectionVariants,
  Text,
  TextContent,
  ToolbarContent,
} from "@patternfly/react-core";

import { useAdvisoryList } from "./useAdvisoryList";

export const AdvisoryList: React.FC = () => {
  const { tableProps, table } = useAdvisoryList();

  const {
    components: { Toolbar, FilterToolbar, PaginationToolbarItem, Pagination },
  } = tableProps;

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <TextContent>
          <Text component="h1">Advisories</Text>
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
                id="advisory-toolbar"
                {...{ showFiltersSideBySide: true }}
              />
              <PaginationToolbarItem>
                <Pagination
                  variant="top"
                  isCompact
                  widgetId="advisories-pagination-top"
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

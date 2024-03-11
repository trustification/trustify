import React from "react";

import {
  PageSection,
  PageSectionVariants,
  Text,
  TextContent,
  ToolbarContent,
} from "@patternfly/react-core";

import { useSbomList } from "./useSbomList";

export const SbomList: React.FC = () => {
  const { tableProps, table } = useSbomList();

  const {
    components: { Toolbar, FilterToolbar, PaginationToolbarItem, Pagination },
  } = tableProps;

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <TextContent>
          <Text component="h1">SBOMs</Text>
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
                id="sboms-toolbar"
                {...{ showFiltersSideBySide: true }}
              />
              <PaginationToolbarItem>
                <Pagination
                  variant="top"
                  isCompact
                  widgetId="sboms-pagination-top"
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

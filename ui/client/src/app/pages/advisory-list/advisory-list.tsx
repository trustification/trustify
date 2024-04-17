import React from "react";
import { NavLink } from "react-router-dom";

import {
  Button,
  PageSection,
  PageSectionVariants,
  Text,
  TextContent,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import DownloadIcon from "@patternfly/react-icons/dist/esm/icons/download-icon";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";

import { TablePersistenceKeyPrefixes } from "@app/Constants";
import { FilterToolbar, FilterType } from "@app/components/FilterToolbar";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";
import { SimplePagination } from "@app/components/SimplePagination";
import {
  ConditionalTableBody,
  TableHeaderContentWithControls,
} from "@app/components/TableControls";
import {
  getHubRequestParams,
  useTableControlProps,
  useTableControlState,
} from "@app/hooks/table-controls";
import { useDownload } from "@app/hooks/useDownload";
import { useSelectionState } from "@app/hooks/useSelectionState";
import { useFetchAdvisories } from "@app/queries/advisories";

import { CVEGalleryCount } from "./components/CVEsGaleryCount";
import { UploadFilesDrawer } from "./components/UploadFilesDrawer";

export const AdvisoryList: React.FC = () => {
  const [showUploadComponent, setShowUploadComponent] = React.useState(false);

  const tableControlState = useTableControlState({
    tableName: "advisories",
    persistenceKeyPrefix: TablePersistenceKeyPrefixes.advisories,
    columnNames: {
      id: "ID",
      title: "Title",
      severity: "Aggregated severity",
      revisionDate: "Revision",
      cves: "CVEs",
      download: "Download",
    },
    isSortEnabled: true,
    sortableColumns: ["id"],
    initialItemsPerPage: 10,
    isFilterEnabled: true,
    filterCategories: [
      {
        categoryKey: "filterText",
        title: "Filter text",
        placeholderText: "Search",
        type: FilterType.search,
      },
    ],
  });

  const {
    result: { data: advisories, total: totalItemCount },
    isFetching,
    fetchError,
  } = useFetchAdvisories(
    getHubRequestParams({
      ...tableControlState,
    })
  );

  const tableControls = useTableControlProps({
    ...tableControlState,
    idProperty: "id",
    currentPageItems: advisories,
    totalItemCount,
    isLoading: isFetching,
    selectionState: useSelectionState({
      items: advisories,
      isEqual: (a, b) => a.id === b.id,
    }),
  });

  const {
    numRenderedColumns,
    currentPageItems,
    propHelpers: {
      toolbarProps,
      filterToolbarProps,
      paginationToolbarItemProps,
      paginationProps,
      tableProps,
      getThProps,
      getTrProps,
      getTdProps,
    },
  } = tableControls;

  const { downloadAdvisory } = useDownload();

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
          <Toolbar {...toolbarProps}>
            <ToolbarContent>
              <FilterToolbar showFiltersSideBySide {...filterToolbarProps} />
              <ToolbarItem>
                <Button
                  type="button"
                  id="upload-files"
                  aria-label="Upload files"
                  variant="secondary"
                  onClick={() => setShowUploadComponent(true)}
                >
                  Upload files
                </Button>
              </ToolbarItem>
              <ToolbarItem {...paginationToolbarItemProps}>
                <SimplePagination
                  idPrefix="advisories-table"
                  isTop
                  paginationProps={paginationProps}
                />
              </ToolbarItem>
            </ToolbarContent>
          </Toolbar>

          <Table {...tableProps} aria-label="Advisories table">
            <Thead>
              <Tr>
                <TableHeaderContentWithControls {...tableControls}>
                  <Th {...getThProps({ columnKey: "id" })} />
                  <Th {...getThProps({ columnKey: "title" })} />
                  <Th {...getThProps({ columnKey: "severity" })} />
                  <Th {...getThProps({ columnKey: "revisionDate" })} />
                  <Th {...getThProps({ columnKey: "cves" })} />
                  <Th {...getThProps({ columnKey: "download" })} />
                </TableHeaderContentWithControls>
              </Tr>
            </Thead>
            <ConditionalTableBody
              isLoading={isFetching}
              isError={!!fetchError}
              isNoData={totalItemCount === 0}
              numRenderedColumns={numRenderedColumns}
            >
              {currentPageItems.map((item) => {
                return (
                  <Tbody key={item.id}>
                    <Tr {...getTrProps({ item })}>
                      <Td width={15} {...getTdProps({ columnKey: "id" })}>
                        <NavLink to={`/advisories/${item.id}`}>
                          {item.id}
                        </NavLink>
                      </Td>
                      <Td
                        width={40}
                        modifier="truncate"
                        {...getTdProps({ columnKey: "title" })}
                      >
                        {item.title}
                      </Td>
                      <Td
                        width={10}
                        modifier="truncate"
                        {...getTdProps({ columnKey: "severity" })}
                      >
                        <SeverityShieldAndText
                          value={item.severity}
                        />
                      </Td>
                      <Td
                        width={10}
                        modifier="truncate"
                        {...getTdProps({ columnKey: "revisionDate" })}
                      >
                        <SeverityShieldAndText
                          value={item.severity}
                        />
                      </Td>
                      <Td
                        width={15}
                        modifier="truncate"
                        {...getTdProps({ columnKey: "cves" })}
                      >
                        <CVEGalleryCount cves={item.cves} />
                      </Td>
                      <Td
                        width={10}
                        modifier="truncate"
                        {...getTdProps({ columnKey: "download" })}
                      >
                        <Button
                          variant="plain"
                          aria-label="Download"
                          onClick={() => {
                            downloadAdvisory(item.id);
                          }}
                        >
                          <DownloadIcon />
                        </Button>
                      </Td>
                    </Tr>
                  </Tbody>
                );
              })}
            </ConditionalTableBody>
          </Table>
          <SimplePagination
            idPrefix="advisories-table"
            isTop={false}
            isCompact
            paginationProps={paginationProps}
          />
        </div>
      </PageSection>

      <UploadFilesDrawer
        isExpanded={showUploadComponent}
        onCloseClick={() => setShowUploadComponent(false)}
      />
    </>
  );
};

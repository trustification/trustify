import React from "react";
import { NavLink } from "react-router-dom";

import {
  Label,
  PageSection,
  PageSectionVariants,
  Text,
  TextContent,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";

import { TablePersistenceKeyPrefixes } from "@app/Constants";
import { FilterToolbar, FilterType } from "@app/components/FilterToolbar";
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
import { useSelectionState } from "@app/hooks/useSelectionState";
import { useFetchPackages } from "@app/queries/packages";

import { CVEGalleryCount } from "../advisory-list/components/CVEsGaleryCount";

export const PackageList: React.FC = () => {
  const tableControlState = useTableControlState({
    tableName: "packages",
    persistenceKeyPrefix: TablePersistenceKeyPrefixes.packages,
    columnNames: {
      name: "Name",
      namespace: "Namespace",
      version: "Version",
      type: "Type",
      path: "Path",
      qualifiers: "Qualifiers",
      cve: "CVEs",
    },
    isSortEnabled: true,
    sortableColumns: [],
    initialItemsPerPage: 10,
    isFilterEnabled: true,
    filterCategories: [
      {
        categoryKey: "filterText",
        title: "Filter text",
        placeholderText: "Search",
        type: FilterType.search,
      },
      {
        categoryKey: "type",
        title: "Type",
        placeholderText: "Type",
        type: FilterType.multiselect,
        selectOptions: [
          { label: "maven", value: "Maven" },
          { label: "rpm", value: "RPM" },
          { label: "npm", value: "NPM" },
          { label: "oci", value: "OCI" },
        ],
      },
      {
        categoryKey: "qualifier:arch",
        title: "Architecture",
        placeholderText: "Architecture",
        type: FilterType.multiselect,
        selectOptions: [
          { label: "x86_64", value: "AMD 64Bit" },
          { label: "aarch64", value: "ARM 64bit" },
          { label: "ppc64le", value: "PowerPC" },
          { label: "s390x", value: "S390" },
        ],
      },
    ],
  });

  const {
    result: { data: advisories, total: totalItemCount },
    isFetching,
    fetchError,
  } = useFetchPackages(
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
          <Toolbar {...toolbarProps}>
            <ToolbarContent>
              <FilterToolbar showFiltersSideBySide {...filterToolbarProps} />
              <ToolbarItem {...paginationToolbarItemProps}>
                <SimplePagination
                  idPrefix="packages-table"
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
                  <Th {...getThProps({ columnKey: "name" })} />
                  <Th {...getThProps({ columnKey: "namespace" })} />
                  <Th {...getThProps({ columnKey: "version" })} />
                  <Th {...getThProps({ columnKey: "type" })} />
                  <Th {...getThProps({ columnKey: "path" })} />
                  <Th {...getThProps({ columnKey: "qualifiers" })} />
                  <Th {...getThProps({ columnKey: "cve" })} />
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
                      <Td width={25} {...getTdProps({ columnKey: "name" })}>
                        <NavLink
                          to={`/packages/${encodeURIComponent(item.id)}`}
                        >
                          {item.id}
                        </NavLink>
                      </Td>
                      <Td width={15} {...getTdProps({ columnKey: "version" })}>
                        {item.version}
                      </Td>
                      <Td
                        width={10}
                        modifier="truncate"
                        {...getTdProps({ columnKey: "type" })}
                      >
                        {item.type}
                      </Td>
                      <Td
                        width={10}
                        modifier="truncate"
                        {...getTdProps({ columnKey: "path" })}
                      >
                        {item.path}
                      </Td>
                      <Td
                        width={20}
                        {...getTdProps({ columnKey: "qualifiers" })}
                      >
                        {Object.entries(item.qualifiers || {}).map(
                          ([k, v], index) => (
                            <Label key={index} isCompact>{`${k}=${v}`}</Label>
                          )
                        )}
                      </Td>
                      <Td width={10} {...getTdProps({ columnKey: "cve" })}>
                        <CVEGalleryCount cves={item.related_cves} />
                      </Td>
                    </Tr>
                  </Tbody>
                );
              })}
            </ConditionalTableBody>
          </Table>
          <SimplePagination
            idPrefix="packages-table"
            isTop={false}
            isCompact
            paginationProps={paginationProps}
          />
        </div>
      </PageSection>
    </>
  );
};

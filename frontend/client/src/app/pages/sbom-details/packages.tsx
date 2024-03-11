import React from "react";

import { Label, ToolbarContent } from "@patternfly/react-core";
import {
  ExpandableRowContent,
  Td as PFTd,
  Tr as PFTr,
} from "@patternfly/react-table";

import { useFetchPackagesBySbomId } from "@app/queries/sboms";
import {
  ConditionalTableBody,
  FilterType,
  useClientTableBatteries,
} from "@carlosthe19916-latest/react-table-batteries";

interface PackagesProps {
  sbomId: string;
}

export const Packages: React.FC<PackagesProps> = ({ sbomId }) => {
  const { packages, isFetching, fetchError } = useFetchPackagesBySbomId(sbomId);

  const tableControls = useClientTableBatteries({
    idProperty: "id",
    items: packages,
    isLoading: isFetching,
    columnNames: {
      name: "Name",
      namespace: "Namespace",
      version: "Version",
      type: "Type",
      path: "Path",
      qualifiers: "Qualifiers",
      cves: "CVEs",
    },
    filter: {
      isEnabled: true,
      filterCategories: [
        {
          key: "filterText",
          title: "Filter tex",
          type: FilterType.search,
          placeholderText: "Search...",
          getItemValue: (item) => item.name,
        },
      ],
    },
    sort: {
      isEnabled: true,
      sortableColumns: [],
    },
    expansion: {
      isEnabled: true,
      variant: "single",
    },
  });

  const {
    currentPageItems,
    numRenderedColumns,
    components: {
      Table,
      Thead,
      Tr,
      Th,
      Tbody,
      Td,
      Toolbar,
      FilterToolbar,
      PaginationToolbarItem,
      Pagination,
    },
    expansion: { isCellExpanded },
  } = tableControls;

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <FilterToolbar id="packages-toolbar" />
          <PaginationToolbarItem>
            <Pagination
              variant="top"
              isCompact
              widgetId="packages-pagination-top"
            />
          </PaginationToolbarItem>
        </ToolbarContent>
      </Toolbar>

      <Table aria-label="Packages table" className="vertical-aligned-table">
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="name" />
            <Th columnKey="namespace" />
            <Th columnKey="version" />
            <Th columnKey="type" />
            <Th columnKey="path" />
            <Th columnKey="qualifiers" />
            <Th columnKey="cves" />
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={isFetching}
          isError={!!fetchError}
          isNoData={packages?.length === 0}
          numRenderedColumns={numRenderedColumns}
        >
          {currentPageItems?.map((item, rowIndex) => {
            return (
              <Tbody key={item.id}>
                <Tr item={item} rowIndex={rowIndex}>
                  <Td width={15} modifier="truncate" columnKey="name">
                    {item.name}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="namespace">
                    {item.namespace}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="version">
                    {item.version}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="type">
                    {item.type}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="path">
                    {item.path}
                  </Td>
                  <Td width={25} columnKey="qualifiers">
                    {item.qualifiers &&
                      Object.entries(item.qualifiers || {}).map(
                        ([k, v], index) => (
                          <Label key={index} isCompact>{`${k}=${v}`}</Label>
                        )
                      )}
                  </Td>
                  <Td width={20} modifier="truncate" columnKey="cves">
                    TODO list of CVEs
                  </Td>
                </Tr>
                {isCellExpanded(item) ? (
                  <PFTr isExpanded>
                    <PFTd colSpan={7}>
                      <div className="pf-v5-u-m-md">
                        <ExpandableRowContent>
                          TODO: dependency tree + cve list
                        </ExpandableRowContent>
                      </div>
                    </PFTd>
                  </PFTr>
                ) : null}
              </Tbody>
            );
          })}
        </ConditionalTableBody>
      </Table>
      <Pagination
        variant="bottom"
        isCompact
        widgetId="cves-pagination-bottom"
      />
    </>
  );
};

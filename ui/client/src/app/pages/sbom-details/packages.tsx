import React from "react";

import {
  Label,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import {
  ExpandableRowContent,
  Td as PFTd,
  Tr as PFTr,
  Table,
  Tbody,
  Td,
  Th,
  Thead,
  Tr,
} from "@patternfly/react-table";

import { FilterToolbar, FilterType } from "@app/components/FilterToolbar";
import { SimplePagination } from "@app/components/SimplePagination";
import {
  ConditionalTableBody,
  TableHeaderContentWithControls,
} from "@app/components/TableControls";
import { useLocalTableControls } from "@app/hooks/table-controls";
import { useFetchPackagesBySbomId } from "@app/queries/sboms";

interface PackagesProps {
  sbomId: string;
}

export const Packages: React.FC<PackagesProps> = ({ sbomId }) => {
  const { packages, isFetching, fetchError } = useFetchPackagesBySbomId(sbomId);

  const tableControls = useLocalTableControls({
    tableName: "packages-table",
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
    isPaginationEnabled: true,
    initialItemsPerPage: 10,
    isExpansionEnabled: true,
    expandableVariant: "single",
    isFilterEnabled: true,
    filterCategories: [
      {
        categoryKey: "filterText",
        title: "Filter tex",
        type: FilterType.search,
        placeholderText: "Search...",
        getItemValue: (item) => item.name,
      },
    ],
  });

  const {
    currentPageItems,
    numRenderedColumns,
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
    expansionDerivedState: { isCellExpanded },
  } = tableControls;

  return (
    <>
      <Toolbar {...toolbarProps}>
        <ToolbarContent>
          <FilterToolbar showFiltersSideBySide {...filterToolbarProps} />
          <ToolbarItem {...paginationToolbarItemProps}>
            <SimplePagination
              idPrefix="cves-table"
              isTop
              paginationProps={paginationProps}
            />
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>

      <Table {...tableProps} aria-label="CVEs table">
        <Thead>
          <Tr>
            <TableHeaderContentWithControls {...tableControls}>
              <Th {...getThProps({ columnKey: "name" })} />
              <Th {...getThProps({ columnKey: "namespace" })} />
              <Th {...getThProps({ columnKey: "version" })} />
              <Th {...getThProps({ columnKey: "type" })} />
              <Th {...getThProps({ columnKey: "path" })} />
              <Th {...getThProps({ columnKey: "qualifiers" })} />
              <Th {...getThProps({ columnKey: "cves" })} />
            </TableHeaderContentWithControls>
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
                <Tr {...getTrProps({ item })}>
                  <Td
                    width={15}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "name" })}
                  >
                    {item.name}
                  </Td>
                  <Td
                    width={10}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "namespace" })}
                  >
                    {item.namespace}
                  </Td>
                  <Td
                    width={10}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "version" })}
                  >
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
                  <Td width={25} {...getTdProps({ columnKey: "qualifiers" })}>
                    {item.qualifiers &&
                      Object.entries(item.qualifiers || {}).map(
                        ([k, v], index) => (
                          <Label key={index} isCompact>{`${k}=${v}`}</Label>
                        )
                      )}
                  </Td>
                  <Td
                    width={20}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "cves" })}
                  >
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
      <SimplePagination
        idPrefix="packages-table"
        isTop={false}
        isCompact
        paginationProps={paginationProps}
      />
    </>
  );
};

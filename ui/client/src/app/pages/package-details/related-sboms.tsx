import React from "react";
import { NavLink } from "react-router-dom";

import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";

import { SBOMBase } from "@app/api/models";
import { FilterToolbar, FilterType } from "@app/components/FilterToolbar";
import { SimplePagination } from "@app/components/SimplePagination";
import {
  ConditionalTableBody,
  TableHeaderContentWithControls,
} from "@app/components/TableControls";
import { useLocalTableControls } from "@app/hooks/table-controls";

interface RelatedSBOMsProps {
  sboms: SBOMBase[];
}

export const RelatedSBOMs: React.FC<RelatedSBOMsProps> = ({ sboms }) => {
  const tableControls = useLocalTableControls({
    tableName: "sboms-table",
    idProperty: "id",
    items: sboms,
    isLoading: false,
    columnNames: {
      name: "Name",
      version: "Version",
      supplier: "Supplier",
      packageTree: "Package tree",
    },
    hasActionsColumn: true,
    isSortEnabled: false,
    isPaginationEnabled: true,
    initialItemsPerPage: 10,
    isExpansionEnabled: false,
    isFilterEnabled: true,
    filterCategories: [
      {
        categoryKey: "filterText",
        title: "Filter text",
        placeholderText: "Search",
        type: FilterType.search,
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
  } = tableControls;

  return (
    <>
      <Toolbar {...toolbarProps}>
        <ToolbarContent>
          <FilterToolbar showFiltersSideBySide {...filterToolbarProps} />
          <ToolbarItem {...paginationToolbarItemProps}>
            <SimplePagination
              idPrefix="sboms-table"
              isTop
              paginationProps={paginationProps}
            />
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>

      <Table {...tableProps} aria-label="SBOMs table">
        <Thead>
          <Tr>
            <TableHeaderContentWithControls {...tableControls}>
              <Th {...getThProps({ columnKey: "name" })} />
              <Th {...getThProps({ columnKey: "version" })} />
              <Th {...getThProps({ columnKey: "supplier" })} />
              <Th {...getThProps({ columnKey: "packageTree" })} />
            </TableHeaderContentWithControls>
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={false}
          isError={undefined}
          isNoData={sboms.length === 0}
          numRenderedColumns={numRenderedColumns}
        >
          {currentPageItems?.map((item, rowIndex) => {
            return (
              <Tbody key={item.id}>
                <Tr {...getTrProps({ item })}>
                  <Td width={45} {...getTdProps({ columnKey: "name" })}>
                    <NavLink to={`/sboms/${item?.id}`}>{item?.name}</NavLink>
                  </Td>
                  <Td
                    width={15}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "version" })}
                  >
                    {item?.version}
                  </Td>
                  <Td
                    width={25}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "supplier" })}
                  >
                    {item?.supplier}
                  </Td>
                  <Td
                    width={15}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "packageTree" })}
                  >
                    TODO: Package Tree
                  </Td>
                </Tr>
              </Tbody>
            );
          })}
        </ConditionalTableBody>
      </Table>
      <SimplePagination
        idPrefix="sboms-table"
        isTop={false}
        isCompact
        paginationProps={paginationProps}
      />
    </>
  );
};

import React from "react";
import { NavLink } from "react-router-dom";

import { ToolbarContent } from "@patternfly/react-core";

import {
  ConditionalTableBody,
  FilterType,
  useClientTableBatteries,
} from "@carlosthe19916-latest/react-table-batteries";

import { SBOMBase } from "@app/api/models";

interface RelatedSBOMsProps {
  sboms: SBOMBase[];
}

export const RelatedSBOMs: React.FC<RelatedSBOMsProps> = ({ sboms }) => {
  const tableControls = useClientTableBatteries({
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
    filter: {
      isEnabled: true,
      filterCategories: [
        {
          key: "filterText",
          title: "Filter text",
          placeholderText: "Search",
          type: FilterType.search,
          getItemValue: (item) => item.name,
        },
      ],
    },
    sort: {
      isEnabled: true,
      sortableColumns: [],
    },
    pagination: { isEnabled: true },
    expansion: {
      isEnabled: false,
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
  } = tableControls;

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <FilterToolbar id="related-sboms-toolbar" />
          <PaginationToolbarItem>
            <Pagination
              variant="top"
              isCompact
              widgetId="related-sboms-pagination-top"
            />
          </PaginationToolbarItem>
        </ToolbarContent>
      </Toolbar>

      <Table
        aria-label="Related sboms table"
        className="vertical-aligned-table"
      >
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="name" />
            <Th columnKey="version" />
            <Th columnKey="supplier" />
            <Th columnKey="packageTree" />
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={false}
          isNoData={sboms?.length === 0}
          numRenderedColumns={numRenderedColumns}
        >
          {currentPageItems?.map((item, rowIndex) => {
            return (
              <Tbody key={item.id}>
                <Tr item={item} rowIndex={rowIndex}>
                  <Td width={45} columnKey="name">
                    <NavLink to={`/sboms/${item?.id}`}>{item?.name}</NavLink>
                  </Td>
                  <Td width={15} modifier="truncate" columnKey="version">
                    {item?.version}
                  </Td>
                  <Td width={25} modifier="truncate" columnKey="supplier">
                    {item?.supplier}
                  </Td>
                  <Td width={15} modifier="truncate" columnKey="packageTree">
                    TODO: Package Tree
                  </Td>
                </Tr>
              </Tbody>
            );
          })}
        </ConditionalTableBody>
      </Table>
      <Pagination
        variant="bottom"
        isCompact
        widgetId="related-sboms-pagination-bottom"
      />
    </>
  );
};

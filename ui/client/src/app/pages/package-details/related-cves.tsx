import React from "react";
import { NavLink } from "react-router-dom";

import dayjs from "dayjs";

import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";

import { RENDER_DATE_FORMAT } from "@app/Constants";
import { CVEBase } from "@app/api/models";
import { FilterToolbar, FilterType } from "@app/components/FilterToolbar";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";
import { SimplePagination } from "@app/components/SimplePagination";
import {
  ConditionalTableBody,
  TableHeaderContentWithControls,
} from "@app/components/TableControls";
import { useLocalTableControls } from "@app/hooks/table-controls";

interface RelatedCVEsProps {
  cves: CVEBase[];
}

export const RelatedCVEs: React.FC<RelatedCVEsProps> = ({ cves }) => {
  const tableControls = useLocalTableControls({
    tableName: "cves-table",
    idProperty: "id",
    items: cves,
    isLoading: false,
    columnNames: {
      id: "ID",
      description: "Description",
      severity: "Severity",
      datePublished: "Date published",
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
        getItemValue: (item) => item.id,
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
              <Th {...getThProps({ columnKey: "id" })} />
              <Th {...getThProps({ columnKey: "description" })} />
              <Th {...getThProps({ columnKey: "severity" })} />
              <Th {...getThProps({ columnKey: "datePublished" })} />
            </TableHeaderContentWithControls>
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={false}
          isError={undefined}
          isNoData={cves.length === 0}
          numRenderedColumns={numRenderedColumns}
        >
          {currentPageItems?.map((item, rowIndex) => {
            return (
              <Tbody key={item.id}>
                <Tr {...getTrProps({ item })}>
                  <Td width={15} {...getTdProps({ columnKey: "id" })}>
                    <NavLink to={`/cves/${item.id}`}>{item.id}</NavLink>
                  </Td>
                  <Td
                    width={50}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "description" })}
                  >
                    {item.description}
                  </Td>
                  <Td
                    width={15}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "severity" })}
                  >
                    <SeverityShieldAndText value={item.severity} />
                  </Td>
                  <Td
                    width={15}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "datePublished" })}
                  >
                    {dayjs(item.date_discovered).format(RENDER_DATE_FORMAT)}
                  </Td>
                </Tr>
              </Tbody>
            );
          })}
        </ConditionalTableBody>
      </Table>
      <SimplePagination
        idPrefix="cves-table"
        isTop={false}
        isCompact
        paginationProps={paginationProps}
      />
    </>
  );
};

import React from "react";
import { NavLink } from "react-router-dom";

import dayjs from "dayjs";

import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core";
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

interface CVEsProps {
  cves: CVEBase[];
}

export const CVEs: React.FC<CVEsProps> = ({ cves }) => {
  const tableControls = useLocalTableControls({
    tableName: "cves-table",
    idProperty: "id",
    items: cves,
    columnNames: {
      cve: "CVE ID",
      title: "Title",
      discovery: "Discovery",
      release: "Release",
      severity: "Severity",
      cwe: "CWE",
    },
    hasActionsColumn: true,
    isSortEnabled: true,
    sortableColumns: ["cve", "discovery", "release"],
    getSortValues: (vuln) => ({
      cve: vuln?.id || "",
      discovery: vuln ? dayjs(vuln.date_discovered).millisecond() : 0,
      release: vuln ? dayjs(vuln.date_released).millisecond() : 0,
    }),
    isPaginationEnabled: true,
    initialItemsPerPage: 10,
    isExpansionEnabled: true,
    expandableVariant: "single",
    isFilterEnabled: true,
    filterCategories: [
      {
        categoryKey: "cve",
        title: "ID",
        type: FilterType.search,
        placeholderText: "Search by ID...",
        getItemValue: (item) => item.id || "",
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
              <Th {...getThProps({ columnKey: "cve" })} />
              <Th {...getThProps({ columnKey: "title" })} />
              <Th {...getThProps({ columnKey: "discovery" })} />
              <Th {...getThProps({ columnKey: "release" })} />
              <Th {...getThProps({ columnKey: "severity" })} />
              <Th {...getThProps({ columnKey: "cwe" })} />
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
                  <Td width={15} {...getTdProps({ columnKey: "cve" })}>
                    <NavLink to={`/cves/${item.id}`}>{item.id}</NavLink>
                  </Td>
                  <Td
                    width={40}
                    modifier="truncate"
                    {...getTdProps({ columnKey: "title" })}
                  >
                    {item.title}
                  </Td>
                  <Td width={10} {...getTdProps({ columnKey: "discovery" })}>
                    {dayjs(item.date_discovered).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={10} {...getTdProps({ columnKey: "release" })}>
                    {dayjs(item.date_released).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={15} {...getTdProps({ columnKey: "severity" })}>
                    <SeverityShieldAndText value={item.severity} />
                  </Td>
                  <Td width={10} {...getTdProps({ columnKey: "cwe" })}>
                    {item.cwe}
                  </Td>
                </Tr>
                {isCellExpanded(item) ? (
                  <PFTr isExpanded>
                    <PFTd colSpan={7}>
                      <ExpandableRowContent>
                        Some content here
                      </ExpandableRowContent>
                    </PFTd>
                  </PFTr>
                ) : null}
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

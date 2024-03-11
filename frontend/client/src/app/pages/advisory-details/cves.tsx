import { ToolbarContent } from "@patternfly/react-core";
import {
  ExpandableRowContent,
  Td as PFTd,
  Tr as PFTr,
} from "@patternfly/react-table";
import React from "react";
import { NavLink } from "react-router-dom";

import dayjs from "dayjs";

import { RENDER_DATE_FORMAT } from "@app/Constants";

import { CVEBase } from "@app/api/models";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";
import {
  ConditionalTableBody,
  FilterType,
  useClientTableBatteries,
} from "@carlosthe19916-latest/react-table-batteries";

interface CVEsProps {
  cves: CVEBase[];
}

export const CVEs: React.FC<CVEsProps> = ({ cves }) => {
  const tableControls = useClientTableBatteries({
    idProperty: "id",
    items: cves,
    isLoading: false,
    columnNames: {
      cve: "CVE ID",
      title: "Title",
      discovery: "Discovery",
      release: "Release",
      severity: "Severity",
      cwe: "CWE",
    },
    hasActionsColumn: true,
    filter: {
      isEnabled: true,
      filterCategories: [
        {
          key: "cve",
          title: "ID",
          type: FilterType.search,
          placeholderText: "Search by ID...",
          getItemValue: (item) => item.id || "",
        },
      ],
    },
    sort: {
      isEnabled: true,
      sortableColumns: ["cve", "discovery", "release"],
      getSortValues: (vuln) => ({
        cve: vuln?.id || "",
        discovery: vuln ? dayjs(vuln.date_discovered).millisecond() : 0,
        release: vuln ? dayjs(vuln.date_released).millisecond() : 0,
      }),
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
    expansion: { isCellExpanded },
  } = tableControls;

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <FilterToolbar id="cves-toolbar" />
          <PaginationToolbarItem>
            <Pagination
              variant="top"
              isCompact
              widgetId="cves-pagination-top"
            />
          </PaginationToolbarItem>
        </ToolbarContent>
      </Toolbar>

      <Table aria-label="CVEs table" className="vertical-aligned-table">
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="cve" />
            <Th columnKey="title" />
            <Th columnKey="discovery" />
            <Th columnKey="release" />
            <Th columnKey="severity" />
            <Th columnKey="cwe" />
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
                <Tr item={item} rowIndex={rowIndex}>
                  <Td width={15} columnKey="cve">
                    <NavLink to={`/cves/${item.id}`}>{item.id}</NavLink>
                  </Td>
                  <Td width={40} modifier="truncate" columnKey="title">
                    {item.title}
                  </Td>
                  <Td width={10} columnKey="discovery">
                    {dayjs(item.date_discovered).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={10} columnKey="release">
                    {dayjs(item.date_released).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={15} columnKey="severity">
                    <SeverityShieldAndText value={item.severity} />
                  </Td>
                  <Td width={10} columnKey="cwe">
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
      <Pagination
        variant="bottom"
        isCompact
        widgetId="cves-pagination-bottom"
      />
    </>
  );
};

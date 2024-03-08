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

import { AdvisoryVulnerability } from "@app/api/models";
import {
  ConditionalTableBody,
  FilterType,
  useClientTableBatteries,
} from "@carlosthe19916-latest/react-table-batteries";
import { SeverityProgressBar } from "@app/components/SeverityProgressBar";

interface VulnerabilitiesProps {
  vulnerabilities: AdvisoryVulnerability[];
}

export const Vulnerabilities: React.FC<VulnerabilitiesProps> = ({
  vulnerabilities,
}) => {
  const tableControls = useClientTableBatteries({
    idProperty: "id",
    items: vulnerabilities,
    isLoading: false,
    columnNames: {
      cve: "CVE ID",
      title: "Title",
      discovery: "Discovery",
      release: "Release",
      score: "Score",
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
        discovery: vuln ? dayjs(vuln.discovery_date).millisecond() : 0,
        release: vuln ? dayjs(vuln.release_date).millisecond() : 0,
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
          <FilterToolbar id="vulnerabilities-toolbar" />
          <PaginationToolbarItem>
            <Pagination
              variant="top"
              isCompact
              widgetId="vulnerabilities-pagination-top"
            />
          </PaginationToolbarItem>
        </ToolbarContent>
      </Toolbar>

      <Table
        aria-label="Vulnerabilities table"
        className="vertical-aligned-table"
      >
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="cve" />
            <Th columnKey="title" />
            <Th columnKey="discovery" />
            <Th columnKey="release" />
            <Th columnKey="score" />
            <Th columnKey="cwe" />
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={false}
          isError={undefined}
          isNoData={vulnerabilities.length === 0}
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
                    {dayjs(item.discovery_date).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={10} columnKey="release">
                    {dayjs(item.release_date).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={15} columnKey="score">
                    <SeverityProgressBar value={item.score} />
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
        widgetId="vulnerabilities-pagination-bottom"
      />
    </>
  );
};

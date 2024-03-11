import React from "react";
import { NavLink } from "react-router-dom";

import { ToolbarContent } from "@patternfly/react-core";

import dayjs from "dayjs";

import {
  ConditionalTableBody,
  FilterType,
  useClientTableBatteries,
} from "@carlosthe19916-latest/react-table-batteries";

import { RENDER_DATE_FORMAT } from "@app/Constants";
import { CVEBase } from "@app/api/models";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";

interface RelatedCVEsProps {
  cves: CVEBase[];
}

export const RelatedCVEs: React.FC<RelatedCVEsProps> = ({ cves }) => {
  const tableControls = useClientTableBatteries({
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
    filter: {
      isEnabled: true,
      filterCategories: [
        {
          key: "filterText",
          title: "Filter text",
          placeholderText: "Search",
          type: FilterType.search,
          getItemValue: (item) => item.id,
        },
      ],
    },
    sort: {
      isEnabled: true,
      sortableColumns: [],
    },
    pagination: { isEnabled: true },
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
          <FilterToolbar id="related-cves-toolbar" />
          <PaginationToolbarItem>
            <Pagination
              variant="top"
              isCompact
              widgetId="related-cves-pagination-top"
            />
          </PaginationToolbarItem>
        </ToolbarContent>
      </Toolbar>

      <Table aria-label="CVEs table" className="vertical-aligned-table">
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="id" />
            <Th columnKey="description" />
            <Th columnKey="severity" />
            <Th columnKey="datePublished" />
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={false}
          isNoData={cves.length === 0}
          numRenderedColumns={numRenderedColumns}
        >
          {currentPageItems?.map((item, rowIndex) => {
            return (
              <Tbody key={item.id}>
                <Tr item={item} rowIndex={rowIndex}>
                  <Td width={15} columnKey="id">
                    <NavLink to={`/cves/${item.id}`}>{item.id}</NavLink>
                  </Td>
                  <Td width={50} modifier="truncate" columnKey="description">
                    {item.description}
                  </Td>
                  <Td width={15} modifier="truncate" columnKey="severity">
                    <SeverityShieldAndText value={item.severity} />
                  </Td>
                  <Td width={15} modifier="truncate" columnKey="datePublished">
                    {dayjs(item.date_discovered).format(RENDER_DATE_FORMAT)}
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
        widgetId="related-cves-pagination-bottom"
      />
    </>
  );
};

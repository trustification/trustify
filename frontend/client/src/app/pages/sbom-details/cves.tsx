import React from "react";

import { ToolbarContent } from "@patternfly/react-core";
import {
  ExpandableRowContent,
  Td as PFTd,
  Tr as PFTr,
} from "@patternfly/react-table";

import { useFetchCVEsBySbomId } from "@app/queries/sboms";
import {
  ConditionalTableBody,
  FilterType,
  useClientTableBatteries,
} from "@carlosthe19916-latest/react-table-batteries";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";
import dayjs from "dayjs";
import { RENDER_DATE_FORMAT } from "@app/Constants";

interface CVEsProps {
  sbomId: string;
}

export const CVEs: React.FC<CVEsProps> = ({ sbomId }) => {
  const { cves, isFetching, fetchError } = useFetchCVEsBySbomId(sbomId);

  const tableControls = useClientTableBatteries({
    idProperty: "id",
    items: cves,
    isLoading: isFetching,
    columnNames: {
      id: "ID",
      description: "Description",
      severity: "Severity",
      datePublished: "Date published",
      packages: "Packages",
    },
    filter: {
      isEnabled: true,
      filterCategories: [
        {
          key: "filterText",
          title: "Filter tex",
          type: FilterType.search,
          placeholderText: "Search...",
          getItemValue: (item) => item.id,
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
            <Th columnKey="id" />
            <Th columnKey="description" />
            <Th columnKey="severity" />
            <Th columnKey="datePublished" />
            <Th columnKey="packages" />
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={isFetching}
          isError={!!fetchError}
          isNoData={cves?.length === 0}
          numRenderedColumns={numRenderedColumns}
        >
          {currentPageItems?.map((item, rowIndex) => {
            return (
              <Tbody key={item.id}>
                <Tr item={item} rowIndex={rowIndex}>
                  <Td width={15} modifier="truncate" columnKey="id">
                    {item.id}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="description">
                    {item.description}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="severity">
                    <SeverityShieldAndText value={item.severity} />
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="datePublished">
                    {dayjs(item.date_discovered).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="packages">
                    TODO packages affected
                  </Td>
                </Tr>
                {isCellExpanded(item) ? (
                  <PFTr isExpanded>
                    <PFTd colSpan={7}>
                      <div className="pf-v5-u-m-md">
                        <ExpandableRowContent>
                          TODO: CVE details and package tree details
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

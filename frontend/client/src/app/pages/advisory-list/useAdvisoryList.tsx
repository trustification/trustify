import { Button } from "@patternfly/react-core";
import {
  ExpandableRowContent,
  Td as PFTd,
  Tr as PFTr,
} from "@patternfly/react-table";
import React from "react";
import { NavLink } from "react-router-dom";

import dayjs from "dayjs";

import {
  ConditionalTableBody,
  FilterType,
  useTablePropHelpers,
  useTableState,
} from "@carlosthe19916-latest/react-table-batteries";
import DownloadIcon from "@patternfly/react-icons/dist/esm/icons/download-icon";

import { useDownload } from "@app/hooks/useDownload";
import { getHubRequestParams } from "@app/hooks/table-controls";

import {
  RENDER_DATE_FORMAT,
  TablePersistenceKeyPrefixes,
} from "@app/Constants";
import { useFetchAdvisories } from "@app/queries/advisories";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";
import { VulnerabilitiesCount } from "./components/VulnerabilitiesCount";

export const useAdvisoryList = () => {
  const tableState = useTableState({
    persistenceKeyPrefix: TablePersistenceKeyPrefixes.advisories,
    columnNames: {
      id: "ID",
      title: "Title",
      severity: "Aggregated severity",
      revisionDate: "Revision",
      vulnerabilities: "Vulnerabilities",
      download: "Download",
    },
    filter: {
      isEnabled: true,
      filterCategories: [
        {
          key: "filterText",
          title: "Filter text",
          placeholderText: "Search",
          type: FilterType.search,
        },
        {
          key: "severity",
          title: "Severity",
          placeholderText: "Severity",
          type: FilterType.multiselect,
          selectOptions: [
            { key: "low", value: "Low" },
            { key: "moderate", value: "Moderate" },
            { key: "important", value: "Important" },
            { key: "critical", value: "Critical" },
          ],
        },
      ],
    },
    sort: {
      isEnabled: true,
      sortableColumns: ["severity"],
    },
    pagination: { isEnabled: true },
    expansion: {
      isEnabled: false,
      variant: "single",
    },
  });

  const { filter, cacheKey } = tableState;
  const hubRequestParams = React.useMemo(() => {
    return getHubRequestParams({
      ...tableState,
      filterCategories: filter.filterCategories,
      hubSortFieldKeys: {
        severity: "severity",
      },
    });
  }, [cacheKey]);

  const { isFetching, fetchError, result } =
    useFetchAdvisories(hubRequestParams);

  const tableProps = useTablePropHelpers({
    ...tableState,
    idProperty: "id",
    isLoading: isFetching,
    currentPageItems: result.data,
    totalItemCount: result.total,
  });

  const {
    currentPageItems,
    numRenderedColumns,
    components: { Table, Thead, Tr, Th, Tbody, Td, Pagination },
    expansion: { isCellExpanded },
  } = tableProps;

  const { downloadAdvisory } = useDownload();

  const table = (
    <>
      <Table aria-label="Advisory details table">
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="id" />
            <Th columnKey="title" />
            <Th columnKey="severity" />
            <Th columnKey="revisionDate" />
            <Th columnKey="vulnerabilities" />
            <Th columnKey="download" />
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={isFetching}
          isError={!!fetchError}
          isNoData={result.total === 0}
          numRenderedColumns={numRenderedColumns}
        >
          {currentPageItems?.map((item, rowIndex) => {
            return (
              <Tbody key={item.id}>
                <Tr item={item} rowIndex={rowIndex}>
                  <Td width={15} columnKey="id">
                    <NavLink to={`/advisories/${item.id}`}>{item.id}</NavLink>
                  </Td>
                  <Td width={40} modifier="truncate" columnKey="title">
                    {item.metadata.title}
                  </Td>
                  <Td width={10} columnKey="severity">
                    <SeverityShieldAndText
                      value={item.aggregated_severity}
                      showLabel
                    />
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="revisionDate">
                    {dayjs(item.revision_date).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={15} columnKey="vulnerabilities">
                    <VulnerabilitiesCount
                      severities={item.vulnerabilities_count}
                    />
                  </Td>
                  <Td width={10} columnKey="download">
                    <Button
                      variant="plain"
                      aria-label="Download"
                      onClick={() => {
                        downloadAdvisory(item.id);
                      }}
                    >
                      <DownloadIcon />
                    </Button>
                  </Td>
                </Tr>
                {isCellExpanded(item) ? (
                  <PFTr isExpanded>
                    <PFTd colSpan={7}>
                      <ExpandableRowContent>
                        {/* <AdvisoryDetails id={item.id} /> */}
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
        widgetId="advisories-pagination-bottom"
      />
    </>
  );

  return {
    tableProps,
    isFetching,
    fetchError,
    total: result.total,
    table,
  };
};

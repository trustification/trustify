import React from "react";
import { NavLink } from "react-router-dom";

import dayjs from "dayjs";

import {
  ConditionalTableBody,
  FilterType,
  useTablePropHelpers,
  useTableState,
} from "@carlosthe19916-latest/react-table-batteries";
import { Button } from "@patternfly/react-core";
import DownloadIcon from "@patternfly/react-icons/dist/esm/icons/download-icon";

import { getHubRequestParams } from "@app/hooks/table-controls";

import {
  RENDER_DATE_FORMAT,
  TablePersistenceKeyPrefixes,
} from "@app/Constants";
import { CveGallery } from "@app/components/CveGallery";
import { useDownload } from "@app/hooks/useDownload";
import { useFetchSBOMs } from "@app/queries/sboms";

export const useSbomList = () => {
  const tableState = useTableState({
    persistenceKeyPrefix: TablePersistenceKeyPrefixes.packages,
    columnNames: {
      name: "Name",
      version: "Version",
      supplier: "Supplier",
      createdOn: "Created on",
      packages: "Packages",
      cves: "CVEs",
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
      ],
    },
    sort: {
      isEnabled: true,
      sortableColumns: ["createdOn"],
    },
    pagination: { isEnabled: true },
  });

  const { filter, cacheKey } = tableState;
  const hubRequestParams = React.useMemo(() => {
    return getHubRequestParams({
      ...tableState,
      filterCategories: filter.filterCategories,
      hubSortFieldKeys: {
        createdOn: "created",
      },
    });
  }, [cacheKey]);

  const { isFetching, result, fetchError } = useFetchSBOMs(hubRequestParams);

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
  } = tableProps;

  const { downloadSBOM } = useDownload();

  const table = (
    <>
      <Table aria-label="Sboms details table">
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="name" />
            <Th columnKey="version" />
            <Th columnKey="supplier" />
            <Th columnKey="createdOn" />
            <Th columnKey="packages" />
            <Th columnKey="cves" />
            <Th columnKey="download" />
          </Tr>
        </Thead>
        <ConditionalTableBody
          isLoading={isFetching}
          isError={!!fetchError}
          isNoData={result.total === 0}
          numRenderedColumns={numRenderedColumns}
        >
          <Tbody>
            {currentPageItems?.map((item, rowIndex) => {
              return (
                <Tr key={item.id} item={item} rowIndex={rowIndex}>
                  <Td width={20} columnKey="name">
                    <NavLink to={`/sboms/${item.id}`}>{item.name}</NavLink>
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="version">
                    {item.version}
                  </Td>
                  <Td width={20} columnKey="supplier">
                    {item.supplier}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="createdOn">
                    {dayjs(item.created_on).format(RENDER_DATE_FORMAT)}
                  </Td>
                  <Td width={10} columnKey="packages">
                    {item.related_packages.count}
                  </Td>
                  <Td width={20} columnKey="cves">
                    <CveGallery severities={item.related_cves} />
                  </Td>
                  <Td width={10} columnKey="download">
                    <Button
                      variant="plain"
                      aria-label="Download"
                      onClick={() => {
                        downloadSBOM(item.id);
                      }}
                    >
                      <DownloadIcon />
                    </Button>
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </ConditionalTableBody>
      </Table>
      <Pagination
        variant="bottom"
        isCompact
        widgetId="sboms-pagination-bottom"
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

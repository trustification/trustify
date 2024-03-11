import React from "react";
import { NavLink } from "react-router-dom";

import { Label } from "@patternfly/react-core";

import {
  ConditionalTableBody,
  FilterType,
  useTablePropHelpers,
  useTableState,
} from "@carlosthe19916-latest/react-table-batteries";

import { getHubRequestParams } from "@app/hooks/table-controls";

import { TablePersistenceKeyPrefixes } from "@app/Constants";
import { useFetchPackages } from "@app/queries/packages";
import { CVEGalleryCount } from "../advisory-list/components/CVEsGaleryCount";

export const usePackageList = () => {
  const tableState = useTableState({
    persistenceKeyPrefix: TablePersistenceKeyPrefixes.sboms,
    columnNames: {
      name: "Name",
      namespace: "Namespace",
      version: "Version",
      type: "Type",
      path: "Path",
      qualifiers: "Qualifiers",
      cve: "CVEs",
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
          key: "type",
          title: "Type",
          placeholderText: "Type",
          type: FilterType.multiselect,
          selectOptions: [
            { key: "maven", value: "Maven" },
            { key: "rpm", value: "RPM" },
            { key: "npm", value: "NPM" },
            { key: "oci", value: "OCI" },
          ],
        },
        {
          key: "qualifier:arch",
          title: "Architecture",
          placeholderText: "Architecture",
          type: FilterType.multiselect,
          selectOptions: [
            { key: "x86_64", value: "AMD 64Bit" },
            { key: "aarch64", value: "ARM 64bit" },
            { key: "ppc64le", value: "PowerPC" },
            { key: "s390x", value: "S390" },
          ],
        },
      ],
    },
    sort: {
      isEnabled: true,
      sortableColumns: [],
    },
    pagination: { isEnabled: true },
  });

  const { filter, cacheKey } = tableState;
  const hubRequestParams = React.useMemo(() => {
    return getHubRequestParams({
      ...tableState,
      filterCategories: filter.filterCategories,
      hubSortFieldKeys: {
        created: "created",
      },
    });
  }, [cacheKey]);

  const { isFetching, result, fetchError } = useFetchPackages(hubRequestParams);

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

  const table = (
    <>
      <Table aria-label="Packages details table">
        <Thead>
          <Tr isHeaderRow>
            <Th columnKey="name" />
            <Th columnKey="namespace" />
            <Th columnKey="version" />
            <Th columnKey="type" />
            <Th columnKey="path" />
            <Th columnKey="qualifiers" />
            <Th columnKey="cve" />
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
                  <Td width={25} columnKey="name">
                    <NavLink to={`/packages/${encodeURIComponent(item.id)}`}>
                      {item.id}
                    </NavLink>
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="namespace">
                    {item.namespace}
                  </Td>
                  <Td width={15} columnKey="version">
                    {item.version}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="type">
                    {item.type}
                  </Td>
                  <Td width={10} modifier="truncate" columnKey="path">
                    {item.path}
                  </Td>
                  <Td width={20} columnKey="qualifiers">
                    {Object.entries(item.qualifiers || {}).map(
                      ([k, v], index) => (
                        <Label key={index} isCompact>{`${k}=${v}`}</Label>
                      )
                    )}
                  </Td>
                  <Td width={10} columnKey="cve">
                    <CVEGalleryCount cves={item.related_cves} />
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
        widgetId="packages-pagination-bottom"
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

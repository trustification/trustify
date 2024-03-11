import { useQuery } from "@tanstack/react-query";
import { AxiosError } from "axios";

import { HubRequestParams } from "@app/api/models";
import {
  getSBOMs,
  getSBOMById,
  getSBOMSourceById,
  getPackagesBySbomId,
  getCVEsBySbomId,
} from "@app/api/rest";

export const SBOMsQueryKey = "sboms";

export const useFetchSBOMs = (params: HubRequestParams = {}) => {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [SBOMsQueryKey, params],
    queryFn: () => getSBOMs(params),
  });
  return {
    result: {
      data: data?.data || [],
      total: data?.total ?? 0,
      params: data?.params ?? params,
    },
    isFetching: isLoading,
    fetchError: error,
    refetch,
  };
};

export const useFetchSBOMById = (id?: number | string) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [SBOMsQueryKey, id],
    queryFn: () =>
      id === undefined ? Promise.resolve(undefined) : getSBOMById(id),
    enabled: id !== undefined,
  });

  return {
    sbom: data,
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

export const useFetchSBOMSourceById = (id?: number | string) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [SBOMsQueryKey, id, "source"],
    queryFn: () =>
      id === undefined ? Promise.resolve(undefined) : getSBOMSourceById(id),
    enabled: id !== undefined,
  });

  return {
    source: data,
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

export const useFetchPackagesBySbomId = (sbomId: string | number) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [SBOMsQueryKey, sbomId, "packages"],
    queryFn: () =>
      sbomId === undefined
        ? Promise.resolve(undefined)
        : getPackagesBySbomId(sbomId),
    enabled: sbomId !== undefined,
  });

  return {
    packages: data || [],
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

export const useFetchCVEsBySbomId = (sbomId: string | number) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [SBOMsQueryKey, sbomId, "cves"],
    queryFn: () =>
      sbomId === undefined
        ? Promise.resolve(undefined)
        : getCVEsBySbomId(sbomId),
    enabled: sbomId !== undefined,
  });

  return {
    cves: data || [],
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

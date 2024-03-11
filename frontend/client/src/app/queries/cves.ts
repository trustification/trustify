import { useQuery } from "@tanstack/react-query";
import { AxiosError } from "axios";

import { HubRequestParams } from "@app/api/models";
import { getCVEs, getCVEById, getCVESourceById } from "@app/api/rest";

export const CVEsQueryKey = "cves";

export const useFetchCVEs = (params: HubRequestParams = {}) => {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [CVEsQueryKey, params],
    queryFn: () => getCVEs(params),
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

export const useFetchCVEById = (id?: number | string) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [CVEsQueryKey, id],
    queryFn: () =>
      id === undefined ? Promise.resolve(undefined) : getCVEById(id),
    enabled: id !== undefined,
  });

  return {
    cve: data,
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

export const useFetchCVESourceById = (id?: number | string) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [CVEsQueryKey, id, "source"],
    queryFn: () =>
      id === undefined ? Promise.resolve(undefined) : getCVESourceById(id),
    enabled: id !== undefined,
  });

  return {
    source: data,
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

import { useQuery } from "@tanstack/react-query";
import { AxiosError } from "axios";

import { HubRequestParams } from "@app/api/models";
import { getPackages, getPackageById } from "@app/api/rest";

export const PackagessQueryKey = "packages";

export const useFetchPackages = (params: HubRequestParams = {}) => {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [PackagessQueryKey, params],
    queryFn: () => getPackages(params),
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

export const useFetchPackageById = (id?: number | string) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [PackagessQueryKey, id],
    queryFn: () =>
      id === undefined ? Promise.resolve(undefined) : getPackageById(id),
    enabled: id !== undefined,
  });

  return {
    pkg: data,
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";

import { Importer } from "@app/api/models";
import {
  createImporter,
  deleteImporter,
  getImporterById,
  getImporters,
  updateImporter,
} from "@app/api/rest";

export const ImportersQueryKey = "importers";

export const useFetchImporters = (refetchDisabled: boolean = false) => {
  const { isLoading, error, refetch, data } = useQuery({
    queryKey: [ImportersQueryKey],
    queryFn: getImporters,
    refetchInterval: !refetchDisabled ? 5000 : false,
  });

  return {
    importers: data || [],
    isFetching: isLoading,
    fetchError: error,
    refetch,
  };
};

export const useCreateImporterMutation = (
  onSuccess: (res: Importer) => void,
  onError: (err: AxiosError, payload: Importer) => void
) => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (obj) => createImporter(obj.name, obj.configuration),
    onSuccess: ({ data }, _payload) => {
      onSuccess(data);
      queryClient.invalidateQueries({ queryKey: [ImportersQueryKey] });
    },
    onError,
  });
};

export const useFethImporterById = (id?: number | string) => {
  const { data, isLoading, error } = useQuery({
    queryKey: [ImportersQueryKey, id],
    queryFn: () =>
      id === undefined ? Promise.resolve(undefined) : getImporterById(id),
    enabled: id !== undefined,
  });

  return {
    credentials: data,
    isFetching: isLoading,
    fetchError: error as AxiosError,
  };
};

export const useUpdateImporterMutation = (
  onSuccess: (payload: Importer) => void,
  onError: (err: AxiosError, payload: Importer) => void
) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (obj) => updateImporter(obj.name, obj.configuration),
    onSuccess: (_res, payload) => {
      onSuccess(payload);
      queryClient.invalidateQueries({ queryKey: [ImportersQueryKey] });
    },
    onError: onError,
  });
};

export const useDeleteiIporterMutation = (
  onSuccess: (id: number | string) => void,
  onError: (err: AxiosError, id: number | string) => void
) => {
  const queryClient = useQueryClient();

  const { isPending, mutate, error } = useMutation({
    mutationFn: (id: string | number) => deleteImporter(id),
    onSuccess: (_res, id) => {
      onSuccess(id);
      queryClient.invalidateQueries({ queryKey: [ImportersQueryKey] });
    },
    onError: (err: AxiosError, id) => {
      onError(err, id);
      queryClient.invalidateQueries({ queryKey: [ImportersQueryKey] });
    },
  });

  return {
    mutate,
    isPending,
    error,
  };
};

import { HubRequestParams } from "@app/api/models";
import { PaginationState } from "@carlosthe19916-latest/react-table-batteries";

/**
 * Args for getPaginationHubRequestParams
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 */
export interface IGetPaginationHubRequestParamsArgs {
  /**
   * The "source of truth" state for the pagination feature (returned by usePaginationState)
   */
  pagination?: PaginationState;
}

/**
 * Given the state for the pagination feature and additional arguments, returns params the hub API needs to apply the current pagination.
 * - Makes up part of the object returned by getHubRequestParams
 * @see getHubRequestParams
 */
export const getPaginationHubRequestParams = ({
  pagination: paginationState,
}: IGetPaginationHubRequestParamsArgs): Partial<HubRequestParams> => {
  if (!paginationState) return {};
  const { pageNumber, itemsPerPage } = paginationState;
  return { page: { pageNumber, itemsPerPage } };
};

/**
 * Converts the values returned by getPaginationHubRequestParams into the URL query strings expected by the hub API
 * - Appends converted URL params to the given `serializedParams` object for use in the hub API request
 * - Constructs part of the object returned by serializeRequestParamsForHub
 * @see serializeRequestParamsForHub
 */
export const serializePaginationRequestParamsForHub = (
  deserializedParams: HubRequestParams,
  serializedParams: URLSearchParams
) => {
  const { page } = deserializedParams;
  if (page) {
    const { pageNumber, itemsPerPage } = page;
    serializedParams.append("limit", String(itemsPerPage));
    serializedParams.append("offset", String((pageNumber - 1) * itemsPerPage));
  }
};

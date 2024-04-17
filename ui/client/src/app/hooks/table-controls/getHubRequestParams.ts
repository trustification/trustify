// Hub filter/sort/pagination utils
// TODO these could use some unit tests!

import { HubRequestParams } from "@app/api/models";
import {
  IGetFilterHubRequestParamsArgs,
  getFilterHubRequestParams,
  serializeFilterRequestParamsForHub,
} from "./filtering";
import {
  IGetSortHubRequestParamsArgs,
  getSortHubRequestParams,
  serializeSortRequestParamsForHub,
} from "./sorting";
import {
  IGetPaginationHubRequestParamsArgs,
  getPaginationHubRequestParams,
  serializePaginationRequestParamsForHub,
} from "./pagination";

// TODO move this outside this directory as part of decoupling Konveyor-specific code from table-controls.

/**
 * Returns params required to fetch server-filtered/sorted/paginated data from the hub API.
 * - NOTE: This is Konveyor-specific.
 * - Takes "source of truth" state for all table features (returned by useTableControlState),
 * - Call after useTableControlState and before fetching API data and then calling useTableControlProps.
 * - Returns a HubRequestParams object which is structured for easier consumption by other code before the fetch is made.
 * @see useTableControlState
 * @see useTableControlProps
 */
export const getHubRequestParams = <
  TItem,
  TSortableColumnKey extends string,
  TFilterCategoryKey extends string = string,
>(
  args: IGetFilterHubRequestParamsArgs<TItem, TFilterCategoryKey> &
    IGetSortHubRequestParamsArgs<TSortableColumnKey> &
    IGetPaginationHubRequestParamsArgs
): HubRequestParams => ({
  ...getFilterHubRequestParams(args),
  ...getSortHubRequestParams(args),
  ...getPaginationHubRequestParams(args),
});

/**
 * Converts the HubRequestParams object created above into URLSearchParams (the browser API object for URL query parameters).
 * - NOTE: This is Konveyor-specific.
 * - Used internally by the application's useFetch[Resource] hooks
 */
export const serializeRequestParamsForHub = (
  deserializedParams: HubRequestParams
): URLSearchParams => {
  const serializedParams = new URLSearchParams();
  serializeFilterRequestParamsForHub(deserializedParams, serializedParams);
  serializeSortRequestParamsForHub(deserializedParams, serializedParams);
  serializePaginationRequestParamsForHub(deserializedParams, serializedParams);
  return serializedParams;
};

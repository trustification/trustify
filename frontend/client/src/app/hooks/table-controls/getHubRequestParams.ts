// Hub filter/sort/pagination utils
// TODO these could use some unit tests!

import { HubRequestParams } from "@app/api/models";
import {
  serializeFilterRequestParamsForHub,
  getFilterHubRequestParams,
  IGetFilterHubRequestParamsArgs,
} from "./getFilterHubRequestParams";
import {
  serializeSortRequestParamsForHub,
  getSortHubRequestParams,
  IGetSortHubRequestParamsArgs,
} from "./getSortHubRequestParams";
import {
  serializePaginationRequestParamsForHub,
  getPaginationHubRequestParams,
  IGetPaginationHubRequestParamsArgs,
} from "./getPaginationHubRequestParams";

/**
 * Returns params required to fetch server-filtered/sorted/paginated data from the hub API.
 * - NOTE: This is Hub-specific.
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
 * - NOTE: This is Hub-specific.
 * - Used internally by the application's useFetch[Resource] hooks
 */
export const serializeRequestParamsForHub = (
  deserializedParams: HubRequestParams
): URLSearchParams => {
  const serializedParams = new URLSearchParams();
  serializeFilterRequestParamsForHub(deserializedParams, serializedParams);
  serializeSortRequestParamsForHub(deserializedParams, serializedParams);
  serializePaginationRequestParamsForHub(deserializedParams, serializedParams);

  // Sikula forces sort to have "sorting" data within the query itself
  // rather than its own queryParams, therefore:
  if (serializedParams.has("q") && serializedParams.has("sort")) {
    serializedParams.set(
      "q",
      `${serializedParams.get("q")} (${serializedParams.get("sort")})`
    );
    serializedParams.delete("sort");
  } else if (serializedParams.has("sort")) {
    serializedParams.set("q", `(${serializedParams.get("sort")})`);
    serializedParams.delete("sort");
  }

  return serializedParams;
};

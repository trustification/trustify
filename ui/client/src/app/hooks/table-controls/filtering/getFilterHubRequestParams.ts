import { HubFilter, HubRequestParams } from "@app/api/models";
import { objectKeys } from "@app/utils/utils";
import {
  FilterCategory,
  getFilterLogicOperator,
} from "@app/components/FilterToolbar";
import { IFilterState } from "./useFilterState";

/**
 * Helper function for getFilterHubRequestParams
 * Given a new filter, determines whether there is an existing filter for that hub field and either creates one or merges this filter with the existing one.
 * - If we have multiple UI filters using the same hub field, we need to AND them and pass them to the hub as one filter.
 */
const pushOrMergeFilter = (
  existingFilters: HubFilter[],
  newFilter: HubFilter
) => {
  const existingFilterIndex = existingFilters.findIndex(
    (f) => f.field === newFilter.field
  );
  const existingFilter =
    existingFilterIndex === -1 ? null : existingFilters[existingFilterIndex];
  // We only want to merge filters in specific conditions:
  if (
    existingFilter && // There is a filter to merge with
    existingFilter.operator === newFilter.operator && // It is using the same comparison operator as the new filter (=, ~)
    typeof newFilter.value !== "object" && // The new filter isn't already a list (nested lists are not supported)
    (typeof existingFilter.value !== "object" || // The existing filter isn't already a list, or...
      existingFilter.value.operator === "AND") // ...it is and it's an AND list (already merged once)
  ) {
    const mergedFilter: HubFilter =
      typeof existingFilter.value === "object"
        ? {
            ...existingFilter,
            value: {
              ...existingFilter.value,
              list: [...existingFilter.value.list, newFilter.value],
            },
          }
        : {
            ...existingFilter,
            value: {
              list: [existingFilter.value, newFilter.value],
              operator: "AND",
            },
          };
    existingFilters[existingFilterIndex] = mergedFilter;
  } else {
    existingFilters.push(newFilter);
  }
};

/**
 * Args for getFilterHubRequestParams
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 */
export interface IGetFilterHubRequestParamsArgs<
  TItem,
  TFilterCategoryKey extends string = string,
> {
  /**
   * The "source of truth" state for the filter feature (returned by useFilterState)
   */
  filterState?: IFilterState<TFilterCategoryKey>;
  /**
   * Definitions of the filters to be used (must include `getItemValue` functions for each category when performing filtering locally)
   */
  filterCategories?: FilterCategory<TItem, TFilterCategoryKey>[];
  implicitFilters?: HubFilter[];
}

/**
 * Given the state for the filter feature and additional arguments, returns params the hub API needs to apply the current filters.
 * - Makes up part of the object returned by getHubRequestParams
 * @see getHubRequestParams
 */
export const getFilterHubRequestParams = <
  TItem,
  TFilterCategoryKey extends string = string,
>({
  filterState,
  filterCategories,
  implicitFilters,
}: IGetFilterHubRequestParamsArgs<
  TItem,
  TFilterCategoryKey
>): Partial<HubRequestParams> => {
  if (
    !implicitFilters?.length &&
    (!filterState ||
      !filterCategories ||
      objectKeys(filterState.filterValues).length === 0)
  ) {
    return {};
  }
  const filters: HubFilter[] = [];
  if (filterState) {
    const { filterValues } = filterState;
    objectKeys(filterValues).forEach((categoryKey) => {
      const filterCategory = filterCategories?.find(
        (category) => category.categoryKey === categoryKey
      );
      const filterValue = filterValues[categoryKey];
      if (!filterCategory || !filterValue) return;
      const serverFilterField = filterCategory.serverFilterField || categoryKey;
      const serverFilterValue =
        filterCategory.getServerFilterValue?.(filterValue) || filterValue;
      // Note: If we need to support more of the logic operators in HubFilter in the future,
      //       we'll need to figure out how to express those on the FilterCategory objects
      //       and translate them here.
      if (filterCategory.type === "numsearch") {
        pushOrMergeFilter(filters, {
          field: serverFilterField,
          operator: "=",
          value: Number(serverFilterValue[0]),
        });
      }
      if (filterCategory.type === "search") {
        pushOrMergeFilter(filters, {
          field: serverFilterField,
          operator: "~",
          value: serverFilterValue[0],
        });
      }
      if (filterCategory.type === "select") {
        pushOrMergeFilter(filters, {
          field: serverFilterField,
          operator: "=",
          value: serverFilterValue[0],
        });
      }
      if (filterCategory.type === "multiselect") {
        pushOrMergeFilter(filters, {
          field: serverFilterField,
          operator: "=",
          value: {
            list: serverFilterValue,
            operator: getFilterLogicOperator(filterCategory, "OR"),
          },
        });
      }
    });
  }
  if (implicitFilters) {
    implicitFilters.forEach((filter) => filters.push(filter));
  }
  return { filters };
};

/**
 * Helper function for serializeFilterForHub
 * - Given a string or number, returns it as a string with quotes (`"`) around it.
 * - Adds an escape character before any existing quote (`"`) characters in the string.
 */
export const wrapInQuotesAndEscape = (value: string | number): string =>
  `"${String(value).replace('"', '\\"')}"`;

/**
 * Converts a single filter object (HubFilter, the higher-level inspectable type) to the query string filter format used by the hub API
 */
export const serializeFilterForHub = (filter: HubFilter): string => {
  const { field, operator, value } = filter;
  const joinedValue =
    typeof value === "string"
      ? wrapInQuotesAndEscape(value)
      : typeof value === "number"
      ? `"${value}"`
      : `(${value.list
          .map(wrapInQuotesAndEscape)
          .join(value.operator === "OR" ? "|" : ",")})`;
  return `${field}${operator}${joinedValue}`;
};

/**
 * Converts the values returned by getFilterHubRequestParams into the URL query strings expected by the hub API
 * - Appends converted URL params to the given `serializedParams` object for use in the hub API request
 * - Constructs part of the object returned by serializeRequestParamsForHub
 * @see serializeRequestParamsForHub
 */
export const serializeFilterRequestParamsForHub = (
  deserializedParams: HubRequestParams,
  serializedParams: URLSearchParams
) => {
  const { filters } = deserializedParams;
  if (filters) {
    serializedParams.append(
      "filter",
      filters.map(serializeFilterForHub).join(",")
    );
  }
};

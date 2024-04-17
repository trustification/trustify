import { FilterValue, IFilterValues } from "@app/components/FilterToolbar";
import { objectKeys } from "@app/utils/utils";

/**
 * Helper function for useFilterState
 * Given a structured filter values object, returns a string to be stored in the feature's PersistTarget (URL params, localStorage, etc).
 */
export const serializeFilterUrlParams = <TFilterCategoryKey extends string>(
  filterValues: IFilterValues<TFilterCategoryKey>
): { filters?: string | null } => {
  // If a filter value is empty/cleared, don't put it in the object in URL params
  const trimmedFilterValues = { ...filterValues };
  objectKeys(trimmedFilterValues).forEach((filterCategoryKey) => {
    if (
      !trimmedFilterValues[filterCategoryKey] ||
      trimmedFilterValues[filterCategoryKey]?.length === 0
    ) {
      delete trimmedFilterValues[filterCategoryKey];
    }
  });
  return {
    filters:
      objectKeys(trimmedFilterValues).length > 0
        ? JSON.stringify(trimmedFilterValues)
        : null, // If there are no filters, remove the filters param from the URL entirely.
  };
};

/**
 * Helper function for useFilterState
 * Given a string retrieved from the feature's PersistTarget (URL params, localStorage, etc), converts it back to the structured filter values object.
 */
export const deserializeFilterUrlParams = <
  TFilterCategoryKey extends string,
>(serializedParams: {
  filters?: string | null;
}): Partial<Record<TFilterCategoryKey, FilterValue>> => {
  try {
    return JSON.parse(serializedParams.filters || "{}");
  } catch (e) {
    return {};
  }
};

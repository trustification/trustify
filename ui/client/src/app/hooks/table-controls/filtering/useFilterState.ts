import { FilterCategory, IFilterValues } from "@app/components/FilterToolbar";
import { IFeaturePersistenceArgs } from "../types";
import { usePersistentState } from "@app/hooks/usePersistentState";
import { serializeFilterUrlParams } from "./helpers";
import { deserializeFilterUrlParams } from "./helpers";
import { DiscriminatedArgs } from "@app/utils/type-utils";
import { useEffect, useState } from "react";

/**
 * The "source of truth" state for the filter feature.
 * - Included in the object returned by useTableControlState (ITableControlState) under the `filterState` property.
 * - Also included in the `ITableControls` object returned by useTableControlProps and useLocalTableControls.
 * @see ITableControlState
 * @see ITableControls
 */
export interface IFilterState<TFilterCategoryKey extends string> {
  /**
   * A mapping:
   * - from string keys uniquely identifying a filterCategory (inferred from the `key` properties of elements in the `filterCategories` array)
   * - to arrays of strings representing the current value(s) of that filter. Single-value filters are stored as an array with one element.
   */
  filterValues: IFilterValues<TFilterCategoryKey>;
  /**
   * Updates the `filterValues` mapping.
   */
  setFilterValues: (values: IFilterValues<TFilterCategoryKey>) => void;
}

/**
 * Args for useFilterState
 * - Makes up part of the arguments object taken by useTableControlState (IUseTableControlStateArgs)
 * - The properties defined here are only required by useTableControlState if isFilterEnabled is true (see DiscriminatedArgs)
 * - Properties here are included in the `ITableControls` object returned by useTableControlProps and useLocalTableControls.
 * @see IUseTableControlStateArgs
 * @see DiscriminatedArgs
 * @see ITableControls
 */
export type IFilterStateArgs<
  TItem,
  TFilterCategoryKey extends string,
> = DiscriminatedArgs<
  "isFilterEnabled",
  {
    /**
     * Definitions of the filters to be used (must include `getItemValue` functions for each category when performing filtering locally)
     */
    filterCategories: FilterCategory<TItem, TFilterCategoryKey>[];
    initialFilterValues?: IFilterValues<TFilterCategoryKey>;
  }
>;

/**
 * Provides the "source of truth" state for the filter feature.
 * - Used internally by useTableControlState
 * - Takes args defined above as well as optional args for persisting state to a configurable storage target.
 * @see PersistTarget
 */
export const useFilterState = <
  TItem,
  TFilterCategoryKey extends string,
  TPersistenceKeyPrefix extends string = string,
>(
  args: IFilterStateArgs<TItem, TFilterCategoryKey> &
    IFeaturePersistenceArgs<TPersistenceKeyPrefix>
): IFilterState<TFilterCategoryKey> => {
  const { isFilterEnabled, persistTo = "state", persistenceKeyPrefix } = args;

  // We need to know if it's the initial load to avoid overwriting changes to the filter values
  const [isInitialLoad, setIsInitialLoad] = useState(true);

  let initialFilterValues = {};

  if (isInitialLoad) {
    initialFilterValues = isFilterEnabled
      ? args?.initialFilterValues ?? {}
      : {};
  }

  useEffect(() => {
    if (isInitialLoad) {
      setIsInitialLoad(false);
    }
  }, [isInitialLoad]);

  // We won't need to pass the latter two type params here if TS adds support for partial inference.
  // See https://github.com/konveyor/tackle2-ui/issues/1456
  const [filterValues, setFilterValues] = usePersistentState<
    IFilterValues<TFilterCategoryKey>,
    TPersistenceKeyPrefix,
    "filters"
  >({
    isEnabled: !!isFilterEnabled,
    defaultValue: initialFilterValues,
    persistenceKeyPrefix,
    // Note: For the discriminated union here to work without TypeScript getting confused
    //       (e.g. require the urlParams-specific options when persistTo === "urlParams"),
    //       we need to pass persistTo inside each type-narrowed options object instead of outside the ternary.
    ...(persistTo === "urlParams"
      ? {
          persistTo,
          keys: ["filters"],
          serialize: serializeFilterUrlParams,
          deserialize: deserializeFilterUrlParams,
        }
      : persistTo === "localStorage" || persistTo === "sessionStorage"
      ? { persistTo, key: "filters" }
      : { persistTo }),
  });
  return { filterValues, setFilterValues };
};

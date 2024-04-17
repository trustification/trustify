import {
  FilterCategory,
  getFilterLogicOperator,
} from "@app/components/FilterToolbar";
import { objectKeys } from "@app/utils/utils";
import { IFilterState } from "./useFilterState";

/**
 * Args for getLocalFilterDerivedState
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by getLocalTableControlDerivedState (ITableControlLocalDerivedStateArgs)
 * @see ITableControlState
 * @see ITableControlLocalDerivedStateArgs
 */
export interface ILocalFilterDerivedStateArgs<
  TItem,
  TFilterCategoryKey extends string,
> {
  /**
   * The API data items before filtering
   */
  items: TItem[];
  /**
   * Definitions of the filters to be used (must include `getItemValue` functions for each category when performing filtering locally)
   */
  filterCategories?: FilterCategory<TItem, TFilterCategoryKey>[];
  /**
   * The "source of truth" state for the filter feature (returned by useFilterState)
   */
  filterState: IFilterState<TFilterCategoryKey>;
}

/**
 * Given the "source of truth" state for the filter feature and additional arguments, returns "derived state" values and convenience functions.
 * - For local/client-computed tables only. Performs the actual filtering logic, which is done on the server for server-computed tables.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export const getLocalFilterDerivedState = <
  TItem,
  TFilterCategoryKey extends string,
>({
  items,
  filterCategories = [],
  filterState: { filterValues },
}: ILocalFilterDerivedStateArgs<TItem, TFilterCategoryKey>) => {
  const filteredItems = items.filter((item) =>
    objectKeys(filterValues).every((categoryKey) => {
      const values = filterValues[categoryKey];
      if (!values || values.length === 0) return true;
      const filterCategory = filterCategories.find(
        (category) => category.categoryKey === categoryKey
      );
      let itemValue = (item as any)[categoryKey];
      if (filterCategory?.getItemValue) {
        itemValue = filterCategory.getItemValue(item);
      }
      const logicOperator = getFilterLogicOperator(filterCategory);
      return values[logicOperator === "AND" ? "every" : "some"](
        (filterValue) => {
          if (!itemValue) return false;
          const lowerCaseItemValue = String(itemValue).toLowerCase();
          const lowerCaseFilterValue = String(filterValue).toLowerCase();
          return lowerCaseItemValue.indexOf(lowerCaseFilterValue) !== -1;
        }
      );
    })
  );
  return { filteredItems };
};

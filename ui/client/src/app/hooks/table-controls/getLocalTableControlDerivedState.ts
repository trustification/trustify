import { getLocalFilterDerivedState } from "./filtering";
import { getLocalSortDerivedState } from "./sorting";
import { getLocalPaginationDerivedState } from "./pagination";
import {
  ITableControlLocalDerivedStateArgs,
  ITableControlDerivedState,
  ITableControlState,
} from "./types";

/**
 * Returns table-level "derived state" (the results of local/client-computed filtering/sorting/pagination)
 * - Used internally by the shorthand hook useLocalTableControls.
 * - Takes "source of truth" state for all features and additional args.
 * @see useLocalTableControls
 */
export const getLocalTableControlDerivedState = <
  TItem,
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
  TFilterCategoryKey extends string = string,
  TPersistenceKeyPrefix extends string = string,
>(
  args: ITableControlState<
    TItem,
    TColumnKey,
    TSortableColumnKey,
    TFilterCategoryKey,
    TPersistenceKeyPrefix
  > &
    ITableControlLocalDerivedStateArgs<
      TItem,
      TColumnKey,
      TSortableColumnKey,
      TFilterCategoryKey
    >
): ITableControlDerivedState<TItem> => {
  const { items, isPaginationEnabled = true } = args;
  const { filteredItems } = getLocalFilterDerivedState({
    ...args,
    items,
  });
  const { sortedItems } = getLocalSortDerivedState({
    ...args,
    items: filteredItems,
  });
  const { currentPageItems } = getLocalPaginationDerivedState({
    ...args,
    items: sortedItems,
  });
  return {
    totalItemCount: filteredItems.length,
    currentPageItems: isPaginationEnabled ? currentPageItems : sortedItems,
  };
};

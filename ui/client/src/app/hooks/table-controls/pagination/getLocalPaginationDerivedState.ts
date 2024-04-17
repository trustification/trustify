import { IPaginationState } from "./usePaginationState";

/**
 * Args for getLocalPaginationDerivedState
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by getLocalTableControlDerivedState (ITableControlLocalDerivedStateArgs)
 * @see ITableControlState
 * @see ITableControlLocalDerivedStateArgs
 */
export interface ILocalPaginationDerivedStateArgs<TItem> {
  /**
   * The API data items before pagination (but after filtering)
   */
  items: TItem[];
  /**
   * The "source of truth" state for the pagination feature (returned by usePaginationState)
   */
  paginationState: IPaginationState;
}

/**
 * Given the "source of truth" state for the pagination feature and additional arguments, returns "derived state" values and convenience functions.
 * - For local/client-computed tables only. Performs the actual pagination logic, which is done on the server for server-computed tables.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export const getLocalPaginationDerivedState = <TItem>({
  items,
  paginationState: { pageNumber, itemsPerPage },
}: ILocalPaginationDerivedStateArgs<TItem>) => {
  const pageStartIndex = (pageNumber - 1) * itemsPerPage;
  const currentPageItems = items.slice(
    pageStartIndex,
    pageStartIndex + itemsPerPage
  );
  return { currentPageItems };
};

import * as React from "react";
import { IPaginationState } from "./usePaginationState";

/**
 * Args for usePaginationEffects
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by useTableControlProps (IUseTableControlPropsArgs)
 */
export interface IUsePaginationEffectsArgs {
  isPaginationEnabled?: boolean;
  paginationState: IPaginationState;
  totalItemCount: number;
  isLoading?: boolean;
}

/**
 * Registers side effects necessary to prevent invalid state related to the pagination feature.
 * - Used internally by usePaginationPropHelpers as part of useTableControlProps
 * - The effect: When API data updates, if there are fewer total items and the current page no longer exists
 *   (e.g. you were on page 11 and now the last page is 10), move to the last page of data.
 */
export const usePaginationEffects = ({
  isPaginationEnabled,
  paginationState: { itemsPerPage, pageNumber, setPageNumber },
  totalItemCount,
  isLoading = false,
}: IUsePaginationEffectsArgs) => {
  // When items are removed, make sure the current page still exists
  const lastPageNumber = Math.max(Math.ceil(totalItemCount / itemsPerPage), 1);
  React.useEffect(() => {
    if (isPaginationEnabled && pageNumber > lastPageNumber && !isLoading) {
      setPageNumber(lastPageNumber);
    }
  });
};

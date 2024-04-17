import { PaginationProps, ToolbarItemProps } from "@patternfly/react-core";
import { IPaginationState } from "./usePaginationState";
import {
  IUsePaginationEffectsArgs,
  usePaginationEffects,
} from "./usePaginationEffects";

/**
 * Args for usePaginationPropHelpers that come from outside useTableControlProps
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by useTableControlProps (IUseTableControlPropsArgs)
 * @see ITableControlState
 * @see IUseTableControlPropsArgs
 */
export type IPaginationPropHelpersExternalArgs = IUsePaginationEffectsArgs & {
  /**
   * The "source of truth" state for the pagination feature (returned by usePaginationState)
   */
  paginationState: IPaginationState;
  /**
    The total number of items in the entire un-filtered, un-paginated table (the size of the entire API collection being tabulated).
   */
  totalItemCount: number;
};

/**
 * Returns derived state and prop helpers for the pagination feature based on given "source of truth" state.
 * - Used internally by useTableControlProps
 * - "Derived state" here refers to values and convenience functions derived at render time.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export const usePaginationPropHelpers = (
  args: IPaginationPropHelpersExternalArgs
) => {
  const {
    totalItemCount,
    paginationState: {
      itemsPerPage,
      pageNumber,
      setPageNumber,
      setItemsPerPage,
    },
  } = args;

  usePaginationEffects(args);

  /**
   * Props for the PF Pagination component
   */
  const paginationProps: PaginationProps = {
    itemCount: totalItemCount,
    perPage: itemsPerPage,
    page: pageNumber,
    onSetPage: (event, pageNumber) => setPageNumber(pageNumber),
    onPerPageSelect: (event, perPage) => {
      setPageNumber(1);
      setItemsPerPage(perPage);
    },
  };

  /**
   * Props for the PF ToolbarItem component which contains the Pagination component
   */
  const paginationToolbarItemProps: ToolbarItemProps = {
    variant: "pagination",
    align: { default: "alignRight" },
  };

  return { paginationProps, paginationToolbarItemProps };
};

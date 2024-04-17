import {
  FilterCategory,
  IFilterToolbarProps,
} from "@app/components/FilterToolbar";
import { IFilterState } from "./useFilterState";
import { ToolbarProps } from "@patternfly/react-core";

/**
 * Args for useFilterPropHelpers that come from outside useTableControlProps
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by useTableControlProps (IUseTableControlPropsArgs)
 * @see ITableControlState
 * @see IUseTableControlPropsArgs
 */
export interface IFilterPropHelpersExternalArgs<
  TItem,
  TFilterCategoryKey extends string,
> {
  /**
   * The "source of truth" state for the filter feature (returned by useFilterState)
   */
  filterState: IFilterState<TFilterCategoryKey>;
  /**
   * Definitions of the filters to be used (must include `getItemValue` functions for each category when performing filtering locally)
   */
  filterCategories?: FilterCategory<TItem, TFilterCategoryKey>[];
}

/**
 * Returns derived state and prop helpers for the filter feature based on given "source of truth" state.
 * - Used internally by useTableControlProps
 * - "Derived state" here refers to values and convenience functions derived at render time.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export const useFilterPropHelpers = <TItem, TFilterCategoryKey extends string>(
  args: IFilterPropHelpersExternalArgs<TItem, TFilterCategoryKey>
) => {
  const {
    filterState: { filterValues, setFilterValues },
    filterCategories = [],
  } = args;

  /**
   * Filter-related props for the PF Toolbar component
   */
  const filterPropsForToolbar: ToolbarProps = {
    collapseListedFiltersBreakpoint: "xl",
    clearAllFilters: () => setFilterValues({}),
    clearFiltersButtonText: "Clear all filters",
  };

  /**
   * Props for the FilterToolbar component (our component for rendering filters)
   */
  const propsForFilterToolbar: IFilterToolbarProps<TItem, TFilterCategoryKey> =
    {
      filterCategories,
      filterValues,
      setFilterValues,
    };

  // TODO fix the confusing naming here... we have FilterToolbar and Toolbar which both have filter-related props
  return { filterPropsForToolbar, propsForFilterToolbar };
};

import { ThProps } from "@patternfly/react-table";
import { ISortState } from "./useSortState";

/**
 * Args for useSortPropHelpers that come from outside useTableControlProps
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by useTableControlProps (IUseTableControlPropsArgs)
 * @see ITableControlState
 * @see IUseTableControlPropsArgs
 */
export interface ISortPropHelpersExternalArgs<
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
> {
  /**
   * The "source of truth" state for the sort feature (returned by useSortState)
   */
  sortState: ISortState<TSortableColumnKey>;
  /**
   * The `columnKey` values (keys of the `columnNames` object passed to useTableControlState) corresponding to columns with sorting enabled
   */
  sortableColumns?: TSortableColumnKey[];
}

/**
 * Additional args for useSortPropHelpers that come from logic inside useTableControlProps
 * @see useTableControlProps
 */
export interface ISortPropHelpersInternalArgs<TColumnKey extends string> {
  /**
   * The keys of the `columnNames` object passed to useTableControlState (for all columns, not just the sortable ones)
   */
  columnKeys: TColumnKey[];
}

/**
 * Returns derived state and prop helpers for the sort feature based on given "source of truth" state.
 * - Used internally by useTableControlProps
 * - "Derived state" here refers to values and convenience functions derived at render time.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export const useSortPropHelpers = <
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
>(
  args: ISortPropHelpersExternalArgs<TColumnKey, TSortableColumnKey> &
    ISortPropHelpersInternalArgs<TColumnKey>
) => {
  const {
    sortState: { activeSort, setActiveSort },
    sortableColumns = [],
    columnKeys,
  } = args;

  /**
   * Returns props for the Th component for a column with sorting enabled.
   */
  const getSortThProps = ({
    columnKey,
  }: {
    columnKey: TSortableColumnKey;
  }): Pick<ThProps, "sort"> =>
    sortableColumns.includes(columnKey)
      ? {
          sort: {
            columnIndex: columnKeys.indexOf(columnKey),
            sortBy: {
              index: activeSort
                ? columnKeys.indexOf(activeSort.columnKey)
                : undefined,
              direction: activeSort?.direction,
            },
            onSort: (event, index, direction) => {
              setActiveSort({
                columnKey: columnKeys[index] as TSortableColumnKey,
                direction,
              });
            },
          },
        }
      : {};

  return { getSortThProps };
};

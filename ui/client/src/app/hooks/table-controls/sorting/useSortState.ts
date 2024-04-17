import { DiscriminatedArgs } from "@app/utils/type-utils";
import { IFeaturePersistenceArgs } from "..";
import { usePersistentState } from "@app/hooks/usePersistentState";

/**
 * The currently applied sort parameters
 */
export interface IActiveSort<TSortableColumnKey extends string> {
  /**
   * The identifier for the currently sorted column (`columnKey` values come from the keys of the `columnNames` object passed to useTableControlState)
   */
  columnKey: TSortableColumnKey;
  /**
   * The direction of the currently applied sort (ascending or descending)
   */
  direction: "asc" | "desc";
}

/**
 * The "source of truth" state for the sort feature.
 * - Included in the object returned by useTableControlState (ITableControlState) under the `sortState` property.
 * - Also included in the `ITableControls` object returned by useTableControlProps and useLocalTableControls.
 * @see ITableControlState
 * @see ITableControls
 */
export interface ISortState<TSortableColumnKey extends string> {
  /**
   * The currently applied sort column and direction
   */
  activeSort: IActiveSort<TSortableColumnKey> | null;
  /**
   * Updates the currently applied sort column and direction
   */
  setActiveSort: (sort: IActiveSort<TSortableColumnKey>) => void;
}

/**
 * Args for useSortState
 * - Makes up part of the arguments object taken by useTableControlState (IUseTableControlStateArgs)
 * - The properties defined here are only required by useTableControlState if isSortEnabled is true (see DiscriminatedArgs)
 * - Properties here are included in the `ITableControls` object returned by useTableControlProps and useLocalTableControls.
 * @see IUseTableControlStateArgs
 * @see DiscriminatedArgs
 * @see ITableControls
 */
export type ISortStateArgs<TSortableColumnKey extends string> =
  DiscriminatedArgs<
    "isSortEnabled",
    {
      /**
       * The `columnKey` values (keys of the `columnNames` object passed to useTableControlState) corresponding to columns with sorting enabled
       */
      sortableColumns: TSortableColumnKey[];
      /**
       * The sort column and direction that should be applied by default when the table first loads
       */
      initialSort?: IActiveSort<TSortableColumnKey> | null;
    }
  >;

/**
 * Provides the "source of truth" state for the sort feature.
 * - Used internally by useTableControlState
 * - Takes args defined above as well as optional args for persisting state to a configurable storage target.
 * @see PersistTarget
 */
export const useSortState = <
  TSortableColumnKey extends string,
  TPersistenceKeyPrefix extends string = string,
>(
  args: ISortStateArgs<TSortableColumnKey> &
    IFeaturePersistenceArgs<TPersistenceKeyPrefix>
): ISortState<TSortableColumnKey> => {
  const { isSortEnabled, persistTo = "state", persistenceKeyPrefix } = args;
  const sortableColumns = (isSortEnabled && args.sortableColumns) || [];
  const initialSort: IActiveSort<TSortableColumnKey> | null = sortableColumns[0]
    ? { columnKey: sortableColumns[0], direction: "asc" }
    : null;

  // We won't need to pass the latter two type params here if TS adds support for partial inference.
  // See https://github.com/konveyor/tackle2-ui/issues/1456
  const [activeSort, setActiveSort] = usePersistentState<
    IActiveSort<TSortableColumnKey> | null,
    TPersistenceKeyPrefix,
    "sortColumn" | "sortDirection"
  >({
    isEnabled: !!isSortEnabled,
    defaultValue: initialSort,
    persistenceKeyPrefix,
    // Note: For the discriminated union here to work without TypeScript getting confused
    //       (e.g. require the urlParams-specific options when persistTo === "urlParams"),
    //       we need to pass persistTo inside each type-narrowed options object instead of outside the ternary.
    ...(persistTo === "urlParams"
      ? {
          persistTo,
          keys: ["sortColumn", "sortDirection"],
          serialize: (activeSort) => ({
            sortColumn: activeSort?.columnKey || null,
            sortDirection: activeSort?.direction || null,
          }),
          deserialize: (urlParams) =>
            urlParams.sortColumn && urlParams.sortDirection
              ? {
                  columnKey: urlParams.sortColumn as TSortableColumnKey,
                  direction: urlParams.sortDirection as "asc" | "desc",
                }
              : null,
        }
      : persistTo === "localStorage" || persistTo === "sessionStorage"
      ? {
          persistTo,
          key: "sort",
        }
      : { persistTo }),
  });
  return { activeSort, setActiveSort };
};

import {
  ITableControlState,
  IUseTableControlStateArgs,
  PersistTarget,
  TableFeature,
} from "./types";
import { useFilterState } from "./filtering";
import { useSortState } from "./sorting";
import { usePaginationState } from "./pagination";
import { useActiveItemState } from "./active-item";
import { useExpansionState } from "./expansion";
import { useColumnState } from "./column/useColumnState";

/**
 * Provides the "source of truth" state for all table features.
 * - State can be persisted in one or more configurable storage targets, either the same for the entire table or different targets per feature.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 * - If you aren't using server-side filtering/sorting/pagination, call this via the shorthand hook useLocalTableControls.
 * - If you are using server-side filtering/sorting/pagination, call this first before fetching your API data and then calling useTableControlProps.
 * @param args
 * @returns
 */
export const useTableControlState = <
  TItem,
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
  TFilterCategoryKey extends string = string,
  TPersistenceKeyPrefix extends string = string,
>(
  args: IUseTableControlStateArgs<
    TItem,
    TColumnKey,
    TSortableColumnKey,
    TFilterCategoryKey,
    TPersistenceKeyPrefix
  >
): ITableControlState<
  TItem,
  TColumnKey,
  TSortableColumnKey,
  TFilterCategoryKey,
  TPersistenceKeyPrefix
> => {
  const getPersistTo = (feature: TableFeature): PersistTarget | undefined =>
    !args.persistTo || typeof args.persistTo === "string"
      ? args.persistTo
      : args.persistTo[feature] || args.persistTo.default;

  const filterState = useFilterState<
    TItem,
    TFilterCategoryKey,
    TPersistenceKeyPrefix
  >({ ...args, persistTo: getPersistTo("filter") });
  const sortState = useSortState<TSortableColumnKey, TPersistenceKeyPrefix>({
    ...args,
    persistTo: getPersistTo("sort"),
  });
  const paginationState = usePaginationState<TPersistenceKeyPrefix>({
    ...args,
    persistTo: getPersistTo("pagination"),
  });
  const expansionState = useExpansionState<TColumnKey, TPersistenceKeyPrefix>({
    ...args,
    persistTo: getPersistTo("expansion"),
  });
  const activeItemState = useActiveItemState<TPersistenceKeyPrefix>({
    ...args,
    persistTo: getPersistTo("activeItem"),
  });

  const { columnNames, tableName } = args;

  const initialColumns = Object.entries(columnNames).map(([id, label]) => ({
    id: id as TColumnKey,
    label: label as string,
    isVisible: true,
  }));

  const columnState = useColumnState<TColumnKey>({
    columnsKey: tableName,
    initialColumns,
  });
  return {
    ...args,
    filterState,
    sortState,
    paginationState,
    expansionState,
    activeItemState,
    columnState,
  };
};

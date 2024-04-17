import { KeyWithValueType } from "@app/utils/type-utils";
import { IExpansionState } from "./useExpansionState";

/**
 * Args for getExpansionDerivedState
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by useTableControlProps (IUseTableControlPropsArgs)
 * @see ITableControlState
 * @see IUseTableControlPropsArgs
 */
export interface IExpansionDerivedStateArgs<TItem, TColumnKey extends string> {
  /**
   * The string key/name of a property on the API data item objects that can be used as a unique identifier (string or number)
   */
  idProperty: KeyWithValueType<TItem, string | number>;
  /**
   * The "source of truth" state for the expansion feature (returned by useExpansionState)
   */
  expansionState: IExpansionState<TColumnKey>;
}

/**
 * Derived state for the expansion feature
 * - "Derived state" here refers to values and convenience functions derived at render time based on the "source of truth" state.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export interface IExpansionDerivedState<TItem, TColumnKey extends string> {
  /**
   * Returns whether a cell or a row is expanded
   *  - If called with a columnKey, returns whether that column's cell in this row is expanded (for compound-expand)
   *  - If called without a columnKey, returns whether the entire row or any cell in it is expanded (for both single-expand and compound-expand)
   */
  isCellExpanded: (item: TItem, columnKey?: TColumnKey) => boolean;
  /**
   * Set a cell or a row as expanded or collapsed
   *  - If called with a columnKey, sets that column's cell in this row expanded or collapsed (for compound-expand)
   *  - If called without a columnKey, sets the entire row as expanded or collapsed (for single-expand)
   */
  setCellExpanded: (args: {
    item: TItem;
    isExpanding?: boolean;
    columnKey?: TColumnKey;
  }) => void;
}

/**
 * Given the "source of truth" state for the expansion feature and additional arguments, returns "derived state" values and convenience functions.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 *
 * NOTE: Unlike `getLocal[Filter|Sort|Pagination]DerivedState`, this is not named `getLocalExpansionDerivedState` because it
 * is always local/client-computed, and it is still used when working with server-computed tables
 * (it's not specific to client-only-computed tables like the other `getLocal*DerivedState` functions are).
 */
export const getExpansionDerivedState = <TItem, TColumnKey extends string>({
  idProperty,
  expansionState: { expandedCells, setExpandedCells },
}: IExpansionDerivedStateArgs<TItem, TColumnKey>): IExpansionDerivedState<
  TItem,
  TColumnKey
> => {
  const isCellExpanded = (item: TItem, columnKey?: TColumnKey) => {
    return columnKey
      ? expandedCells[String(item[idProperty])] === columnKey
      : !!expandedCells[String(item[idProperty])];
  };

  const setCellExpanded = ({
    item,
    isExpanding = true,
    columnKey,
  }: {
    item: TItem;
    isExpanding?: boolean;
    columnKey?: TColumnKey;
  }) => {
    const newExpandedCells = { ...expandedCells };
    if (isExpanding) {
      newExpandedCells[String(item[idProperty])] = columnKey || true;
    } else {
      delete newExpandedCells[String(item[idProperty])];
    }
    setExpandedCells(newExpandedCells);
  };

  return { isCellExpanded, setCellExpanded };
};

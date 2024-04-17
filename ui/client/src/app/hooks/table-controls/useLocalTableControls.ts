import { useTableControlProps } from "./useTableControlProps";
import { ITableControls, IUseLocalTableControlsArgs } from "./types";
import { getLocalTableControlDerivedState } from "./getLocalTableControlDerivedState";
import { useTableControlState } from "./useTableControlState";
import { useSelectionState } from "../useSelectionState";

/**
 * Provides all state, derived state, side-effects and prop helpers needed to manage a local/client-computed table.
 * - Call this and only this if you aren't using server-side filtering/sorting/pagination.
 * - "Derived state" here refers to values and convenience functions derived at render time based on the "source of truth" state.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export const useLocalTableControls = <
  TItem,
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
  TFilterCategoryKey extends string = string,
  TPersistenceKeyPrefix extends string = string,
>(
  args: IUseLocalTableControlsArgs<
    TItem,
    TColumnKey,
    TSortableColumnKey,
    TFilterCategoryKey,
    TPersistenceKeyPrefix
  >
): ITableControls<
  TItem,
  TColumnKey,
  TSortableColumnKey,
  TFilterCategoryKey,
  TPersistenceKeyPrefix
> => {
  const state = useTableControlState(args);
  const derivedState = getLocalTableControlDerivedState({ ...args, ...state });
  const { columnState } = state;
  return useTableControlProps({
    ...args,
    ...state,
    ...derivedState,
    // TODO we won't need this here once selection state is part of useTableControlState
    selectionState: useSelectionState({
      ...args,
      isEqual: (a, b) => a[args.idProperty] === b[args.idProperty],
    }),
    idProperty: args.idProperty,
    ...columnState,
  });
};

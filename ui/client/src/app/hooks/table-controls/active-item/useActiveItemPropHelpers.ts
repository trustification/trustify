import { TrProps } from "@patternfly/react-table";
import {
  IActiveItemDerivedStateArgs,
  getActiveItemDerivedState,
} from "./getActiveItemDerivedState";
import { IActiveItemState } from "./useActiveItemState";
import {
  IUseActiveItemEffectsArgs,
  useActiveItemEffects,
} from "./useActiveItemEffects";

/**
 * Args for useActiveItemPropHelpers that come from outside useTableControlProps
 * - Partially satisfied by the object returned by useTableControlState (ITableControlState)
 * - Makes up part of the arguments object taken by useTableControlProps (IUseTableControlPropsArgs)
 * @see ITableControlState
 * @see IUseTableControlPropsArgs
 */
export type IActiveItemPropHelpersExternalArgs<TItem> =
  IActiveItemDerivedStateArgs<TItem> &
    Omit<IUseActiveItemEffectsArgs<TItem>, "activeItemDerivedState"> & {
      /**
       * Whether the table data is loading
       */
      isLoading?: boolean;
      /**
       * The "source of truth" state for the active item feature (returned by useActiveItemState)
       */
      activeItemState: IActiveItemState;
    };

/**
 * Given "source of truth" state for the active item feature, returns derived state and `propHelpers`.
 * - Used internally by useTableControlProps
 * - Also triggers side effects to prevent invalid state
 * - "Derived state" here refers to values and convenience functions derived at render time.
 * - "source of truth" (persisted) state and "derived state" are kept separate to prevent out-of-sync duplicated state.
 */
export const useActiveItemPropHelpers = <TItem>(
  args: IActiveItemPropHelpersExternalArgs<TItem>
) => {
  const activeItemDerivedState = getActiveItemDerivedState(args);
  const { isActiveItem, setActiveItem, clearActiveItem } =
    activeItemDerivedState;

  useActiveItemEffects({ ...args, activeItemDerivedState });

  /**
   * Returns props for a clickable Tr in a table with the active item feature enabled. Sets or clears the active item when clicked.
   */
  const getActiveItemTrProps = ({
    item,
  }: {
    item: TItem;
  }): Omit<TrProps, "ref"> => ({
    isSelectable: true,
    isClickable: true,
    isRowSelected: item && isActiveItem(item),
    onRowClick: () => {
      if (!isActiveItem(item)) {
        setActiveItem(item);
      } else {
        clearActiveItem();
      }
    },
  });

  return { activeItemDerivedState, getActiveItemTrProps };
};

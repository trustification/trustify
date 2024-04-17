import spacing from "@patternfly/react-styles/css/utilities/Spacing/spacing";

import { objectKeys } from "@app/utils/utils";
import { ITableControls, IUseTableControlPropsArgs } from "./types";
import { useFilterPropHelpers } from "./filtering";
import { useSortPropHelpers } from "./sorting";
import { usePaginationPropHelpers } from "./pagination";
import { useActiveItemPropHelpers } from "./active-item";
import { useExpansionPropHelpers } from "./expansion";
import { handlePropagatedRowClick } from "./utils";

/**
 * Returns derived state and prop helpers for all features. Used to make rendering the table components easier.
 * - Takes "source of truth" state and table-level derived state (derived either on the server or in getLocalTableControlDerivedState)
 *   along with API data and additional args.
 * - Also triggers side-effects for some features to prevent invalid state.
 * - If you aren't using server-side filtering/sorting/pagination, call this via the shorthand hook useLocalTableControls.
 * - If you are using server-side filtering/sorting/pagination, call this last after calling useTableControlState and fetching your API data.
 * @see useLocalTableControls
 * @see useTableControlState
 * @see getLocalTableControlDerivedState
 */
export const useTableControlProps = <
  TItem,
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
  TFilterCategoryKey extends string = string,
  TPersistenceKeyPrefix extends string = string,
>(
  args: IUseTableControlPropsArgs<
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
  type PropHelpers = ITableControls<
    TItem,
    TColumnKey,
    TSortableColumnKey,
    TFilterCategoryKey,
    TPersistenceKeyPrefix
  >["propHelpers"];

  // Note: To avoid repetition, not all args are destructured here since the entire
  //       args object is passed to other other helpers which require other parts of it.
  //       For future additions, inspect `args` to see if it has anything more you need.
  const {
    currentPageItems,
    forceNumRenderedColumns,
    selectionState: {
      selectAll,
      areAllSelected,
      selectedItems,
      selectMultiple,
      toggleItemSelected,
      isItemSelected,
    },
    columnNames,
    hasActionsColumn = false,
    variant,
    isFilterEnabled,
    isSortEnabled,
    isSelectionEnabled,
    isExpansionEnabled,
    isActiveItemEnabled,
    columnState: { columns },
  } = args;

  const columnKeys = objectKeys(columnNames);

  // Some table controls rely on extra columns inserted before or after the ones included in columnNames.
  // We need to account for those when dealing with props based on column index and colSpan.
  let numColumnsBeforeData = 0;
  let numColumnsAfterData = 0;
  if (isSelectionEnabled) numColumnsBeforeData++;
  if (isExpansionEnabled && args.expandableVariant === "single")
    numColumnsBeforeData++;
  if (hasActionsColumn) numColumnsAfterData++;
  const numRenderedColumns =
    forceNumRenderedColumns ||
    columnKeys.length + numColumnsBeforeData + numColumnsAfterData;

  const { filterPropsForToolbar, propsForFilterToolbar } =
    useFilterPropHelpers(args);
  const { getSortThProps } = useSortPropHelpers({ ...args, columnKeys });
  const { paginationProps, paginationToolbarItemProps } =
    usePaginationPropHelpers(args);
  const {
    expansionDerivedState,
    getSingleExpandButtonTdProps,
    getCompoundExpandTdProps,
    getExpandedContentTdProps,
  } = useExpansionPropHelpers({ ...args, columnKeys, numRenderedColumns });
  const { activeItemDerivedState, getActiveItemTrProps } =
    useActiveItemPropHelpers(args);

  const toolbarProps: PropHelpers["toolbarProps"] = {
    className: variant === "compact" ? spacing.pt_0 : "",
    ...(isFilterEnabled && filterPropsForToolbar),
  };

  // TODO move this to a useSelectionPropHelpers when we move selection from lib-ui
  const toolbarBulkSelectorProps: PropHelpers["toolbarBulkSelectorProps"] = {
    onSelectAll: selectAll,
    areAllSelected,
    selectedRows: selectedItems,
    paginationProps,
    currentPageItems,
    onSelectMultiple: selectMultiple,
  };

  const tableProps: PropHelpers["tableProps"] = {
    variant,
    isExpandable: isExpansionEnabled && !!args.expandableVariant,
  };

  const getThProps: PropHelpers["getThProps"] = ({ columnKey }) => ({
    ...(isSortEnabled &&
      getSortThProps({ columnKey: columnKey as TSortableColumnKey })),
    children: columnNames[columnKey],
  });

  const getTrProps: PropHelpers["getTrProps"] = ({ item, onRowClick }) => {
    const activeItemTrProps = getActiveItemTrProps({ item });
    return {
      ...(isActiveItemEnabled && activeItemTrProps),
      onRowClick: (event) =>
        handlePropagatedRowClick(event, () => {
          activeItemTrProps.onRowClick?.(event);
          onRowClick?.(event);
        }),
    };
  };

  const getTdProps: PropHelpers["getTdProps"] = (getTdPropsArgs) => {
    const { columnKey } = getTdPropsArgs;
    return {
      dataLabel: columnNames[columnKey],
      ...(isExpansionEnabled &&
        args.expandableVariant === "compound" &&
        getTdPropsArgs.isCompoundExpandToggle &&
        getCompoundExpandTdProps({
          columnKey,
          item: getTdPropsArgs.item,
          rowIndex: getTdPropsArgs.rowIndex,
        })),
    };
  };

  // TODO move this into a useSelectionPropHelpers and make it part of getTdProps once we move selection from lib-ui
  const getSelectCheckboxTdProps: PropHelpers["getSelectCheckboxTdProps"] = ({
    item,
    rowIndex,
  }) => ({
    select: {
      rowIndex,
      onSelect: (_event, isSelecting) => {
        toggleItemSelected(item, isSelecting);
      },
      isSelected: isItemSelected(item),
    },
  });

  const getColumnVisibility = (columnKey: TColumnKey) => {
    return columns.find((column) => column.id === columnKey)?.isVisible ?? true;
  };

  return {
    ...args,
    numColumnsBeforeData,
    numColumnsAfterData,
    numRenderedColumns,
    expansionDerivedState,
    activeItemDerivedState,
    propHelpers: {
      toolbarProps,
      tableProps,
      getThProps,
      getTrProps,
      getTdProps,
      filterToolbarProps: propsForFilterToolbar,
      paginationProps,
      paginationToolbarItemProps,
      toolbarBulkSelectorProps,
      getSelectCheckboxTdProps,
      getSingleExpandButtonTdProps,
      getExpandedContentTdProps,
      getColumnVisibility,
    },
  };
};

import React from "react";
import { Td } from "@patternfly/react-table";
import { ITableControls } from "@app/hooks/table-controls";

export interface ITableRowContentWithControlsProps<
  TItem,
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
  TFilterCategoryKey extends string = string,
  TPersistenceKeyPrefix extends string = string,
> {
  isExpansionEnabled?: boolean;
  expandableVariant?: "single" | "compound";
  isSelectionEnabled?: boolean;
  propHelpers: ITableControls<
    TItem,
    TColumnKey,
    TSortableColumnKey,
    TFilterCategoryKey,
    TPersistenceKeyPrefix
  >["propHelpers"];
  item: TItem;
  rowIndex: number;
  children: React.ReactNode;
}

export const TableRowContentWithControls = <
  TItem,
  TColumnKey extends string,
  TSortableColumnKey extends TColumnKey,
>({
  isExpansionEnabled = false,
  expandableVariant,
  isSelectionEnabled = false,
  propHelpers: { getSingleExpandButtonTdProps, getSelectCheckboxTdProps },
  item,
  rowIndex,
  children,
}: React.PropsWithChildren<
  ITableRowContentWithControlsProps<TItem, TColumnKey, TSortableColumnKey>
>) => (
  <>
    {isExpansionEnabled && expandableVariant === "single" ? (
      <Td {...getSingleExpandButtonTdProps({ item, rowIndex })} />
    ) : null}
    {isSelectionEnabled ? (
      <Td {...getSelectCheckboxTdProps({ item, rowIndex })} />
    ) : null}
    {children}
  </>
);

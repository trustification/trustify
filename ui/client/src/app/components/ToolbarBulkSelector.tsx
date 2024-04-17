import React, { useState } from "react";
import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownList,
  MenuToggle,
  MenuToggleCheckbox,
  PaginationProps,
  ToolbarItem,
} from "@patternfly/react-core";

import AngleDownIcon from "@patternfly/react-icons/dist/esm/icons/angle-down-icon";
import AngleRightIcon from "@patternfly/react-icons/dist/esm/icons/angle-right-icon";

export interface IToolbarBulkSelectorProps<T> {
  areAllSelected: boolean;
  areAllExpanded?: boolean;
  onSelectAll: (flag: boolean) => void;
  onExpandAll?: (flag: boolean) => void;
  selectedRows: T[];
  onSelectMultiple: (items: T[], isSelecting: boolean) => void;
  currentPageItems: T[];
  paginationProps: PaginationProps;
  isExpandable?: boolean;
}

export const ToolbarBulkSelector = <T,>({
  currentPageItems,
  areAllSelected,
  onSelectAll,
  onExpandAll,
  areAllExpanded,
  selectedRows,
  onSelectMultiple,
  paginationProps,
  isExpandable,
}: React.PropsWithChildren<
  IToolbarBulkSelectorProps<T>
>): JSX.Element | null => {
  const [isOpen, setIsOpen] = useState(false);

  const toggleCollapseAll = (collapse: boolean) => {
    onExpandAll && onExpandAll(!collapse);
  };
  const collapseAllBtn = () => (
    <Button
      variant="control"
      title={`${!areAllExpanded ? "Expand" : "Collapse"} all`}
      onClick={() => {
        areAllExpanded !== undefined && toggleCollapseAll(areAllExpanded);
      }}
    >
      {areAllExpanded ? <AngleDownIcon /> : <AngleRightIcon />}
    </Button>
  );

  const getBulkSelectState = () => {
    let state: boolean | null;
    if (areAllSelected) {
      state = true;
    } else if (selectedRows.length === 0) {
      state = false;
    } else {
      state = null;
    }
    return state;
  };
  const handleSelectAll = (checked: boolean) => {
    onSelectAll(!!checked);
  };

  const dropdownItems = [
    <DropdownItem
      onClick={() => {
        handleSelectAll(false);
      }}
      data-action="none"
      key="select-none"
      component="button"
    >
      Select none (0 items)
    </DropdownItem>,
    <DropdownItem
      onClick={() => {
        onSelectMultiple(
          currentPageItems.map((item: T) => item),
          true
        );
      }}
      data-action="page"
      key="select-page"
      component="button"
    >
      Select page ({currentPageItems.length} items)
    </DropdownItem>,
    <DropdownItem
      onClick={() => {
        handleSelectAll(true);
      }}
      data-action="all"
      key="select-all"
      component="button"
    >
      Select all ({paginationProps.itemCount})
    </DropdownItem>,
  ];

  return (
    <>
      {isExpandable && <ToolbarItem>{collapseAllBtn()}</ToolbarItem>}
      <ToolbarItem>
        <Dropdown
          isOpen={isOpen}
          toggle={(toggleRef) => (
            <MenuToggle
              ref={toggleRef}
              onClick={() => setIsOpen(!isOpen)}
              splitButtonOptions={{
                items: [
                  <MenuToggleCheckbox
                    id="bulk-selected-items-checkbox"
                    key="bulk-select-checkbox"
                    aria-label="Select all"
                    onChange={() => {
                      if (getBulkSelectState() !== false) {
                        onSelectAll(false);
                      } else {
                        onSelectAll(true);
                      }
                    }}
                    isChecked={getBulkSelectState()}
                  />,
                ],
              }}
            />
          )}
        >
          <DropdownList>{dropdownItems}</DropdownList>
        </Dropdown>
      </ToolbarItem>
    </>
  );
};

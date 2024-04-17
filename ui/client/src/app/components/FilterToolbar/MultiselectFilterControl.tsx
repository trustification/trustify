import * as React from "react";
import {
  Badge,
  Button,
  MenuToggle,
  MenuToggleElement,
  Select,
  SelectGroup,
  SelectList,
  SelectOption,
  TextInputGroup,
  TextInputGroupMain,
  TextInputGroupUtilities,
  ToolbarChip,
  ToolbarFilter,
  Tooltip,
} from "@patternfly/react-core";
import { IFilterControlProps } from "./FilterControl";
import {
  IMultiselectFilterCategory,
  FilterSelectOptionProps,
} from "./FilterToolbar";
import { css } from "@patternfly/react-styles";
import { TimesIcon } from "@patternfly/react-icons";

import "./select-overrides.css";

export interface IMultiselectFilterControlProps<TItem>
  extends IFilterControlProps<TItem, string> {
  category: IMultiselectFilterCategory<TItem, string>;
  isScrollable?: boolean;
}

export const MultiselectFilterControl = <TItem,>({
  category,
  filterValue,
  setFilterValue,
  showToolbarItem,
  isDisabled = false,
  isScrollable = false,
}: React.PropsWithChildren<
  IMultiselectFilterControlProps<TItem>
>): JSX.Element | null => {
  const [isFilterDropdownOpen, setIsFilterDropdownOpen] = React.useState(false);

  const [selectOptions, setSelectOptions] = React.useState<
    FilterSelectOptionProps[]
  >(Array.isArray(category.selectOptions) ? category.selectOptions : []);

  React.useEffect(() => {
    setSelectOptions(
      Array.isArray(category.selectOptions) ? category.selectOptions : []
    );
  }, [category.selectOptions]);

  const hasGroupings = !Array.isArray(selectOptions);

  const flatOptions: FilterSelectOptionProps[] = !hasGroupings
    ? selectOptions
    : (Object.values(selectOptions).flatMap(
        (i) => i
      ) as FilterSelectOptionProps[]);

  const getOptionFromOptionValue = (optionValue: string) =>
    flatOptions.find(({ value }) => value === optionValue);

  const [focusedItemIndex, setFocusedItemIndex] = React.useState<number | null>(
    null
  );

  const [activeItem, setActiveItem] = React.useState<string | null>(null);
  const textInputRef = React.useRef<HTMLInputElement>();
  const [inputValue, setInputValue] = React.useState<string>("");

  const onFilterClearAll = () => setFilterValue([]);
  const onFilterClear = (chip: string | ToolbarChip) => {
    const value = typeof chip === "string" ? chip : chip.key;

    if (value) {
      const newValue = filterValue?.filter((val) => val !== value) ?? [];
      setFilterValue(newValue.length > 0 ? newValue : null);
    }
  };

  /*
   * Note: Create chips only as `ToolbarChip` (no plain string)
   */
  const chips = filterValue
    ?.map((value, index) => {
      const option = getOptionFromOptionValue(value);
      if (!option) {
        return null;
      }

      const { chipLabel, label, groupLabel } = option;
      const displayValue: string = chipLabel ?? label ?? value ?? "";

      return {
        key: value,
        node: groupLabel ? (
          <Tooltip
            id={`tooltip-chip-${index}`}
            content={<div>{groupLabel}</div>}
          >
            <div>{displayValue}</div>
          </Tooltip>
        ) : (
          displayValue
        ),
      };
    })

    .filter(Boolean);

  const renderSelectOptions = (
    filter: (option: FilterSelectOptionProps, groupName?: string) => boolean
  ) =>
    hasGroupings
      ? Object.entries(
          selectOptions as Record<string, FilterSelectOptionProps[]>
        )
          .sort(([groupA], [groupB]) => groupA.localeCompare(groupB))
          .map(([group, options]): [string, FilterSelectOptionProps[]] => [
            group,
            options?.filter((o) => filter(o, group)) ?? [],
          ])
          .filter(([, groupFiltered]) => groupFiltered?.length)
          .map(([group, groupFiltered], index) => (
            <SelectGroup key={`group-${index}`} label={group}>
              {groupFiltered.map(({ value, label, optionProps }) => (
                <SelectOption
                  {...optionProps}
                  key={value}
                  value={value}
                  isSelected={filterValue?.includes(value)}
                >
                  {label ?? value}
                </SelectOption>
              ))}
            </SelectGroup>
          ))
      : flatOptions
          .filter((o) => filter(o))
          .map(({ label, value, optionProps = {} }, index) => (
            <SelectOption
              {...optionProps}
              {...(!optionProps.isDisabled && { hasCheckbox: true })}
              key={value}
              value={value}
              isFocused={focusedItemIndex === index}
              isSelected={filterValue?.includes(value)}
            >
              {label ?? value}
            </SelectOption>
          ));

  const onSelect = (value: string | undefined) => {
    if (value && value !== "No results") {
      let newFilterValue: string[];

      if (filterValue && filterValue.includes(value)) {
        newFilterValue = filterValue.filter((item) => item !== value);
      } else {
        newFilterValue = filterValue ? [...filterValue, value] : [value];
      }

      setFilterValue(newFilterValue);
    }
    textInputRef.current?.focus();
  };

  const handleMenuArrowKeys = (key: string) => {
    let indexToFocus = 0;

    if (isFilterDropdownOpen) {
      if (key === "ArrowUp") {
        if (focusedItemIndex === null || focusedItemIndex === 0) {
          indexToFocus = selectOptions.length - 1;
        } else {
          indexToFocus = focusedItemIndex - 1;
        }
      }

      if (key === "ArrowDown") {
        if (
          focusedItemIndex === null ||
          focusedItemIndex === selectOptions.length - 1
        ) {
          indexToFocus = 0;
        } else {
          indexToFocus = focusedItemIndex + 1;
        }
      }

      setFocusedItemIndex(indexToFocus);
      const focusedItem = selectOptions.filter(
        ({ optionProps }) => !optionProps?.isDisabled
      )[indexToFocus];
      setActiveItem(
        `select-multi-typeahead-checkbox-${focusedItem.value.replace(" ", "-")}`
      );
    }
  };

  React.useEffect(() => {
    let newSelectOptions = Array.isArray(category.selectOptions)
      ? category.selectOptions
      : [];

    if (inputValue) {
      newSelectOptions = Array.isArray(category.selectOptions)
        ? category.selectOptions?.filter((menuItem) =>
            String(menuItem.value)
              .toLowerCase()
              .includes(inputValue.trim().toLowerCase())
          )
        : [];

      if (!newSelectOptions.length) {
        newSelectOptions = [
          {
            value: "no-results",
            optionProps: {
              isDisabled: true,
              hasCheckbox: false,
            },
            label: `No results found for "${inputValue}"`,
          },
        ];
      }
    }

    setSelectOptions(newSelectOptions);
    setFocusedItemIndex(null);
    setActiveItem(null);
  }, [inputValue, category.selectOptions]);

  const onInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    const enabledMenuItems = Array.isArray(selectOptions)
      ? selectOptions.filter(({ optionProps }) => !optionProps?.isDisabled)
      : [];
    const [firstMenuItem] = enabledMenuItems;
    const focusedItem = focusedItemIndex
      ? enabledMenuItems[focusedItemIndex]
      : firstMenuItem;

    const newSelectOptions = flatOptions.filter((menuItem) =>
      menuItem.value.toLowerCase().includes(inputValue.toLowerCase())
    );
    const selectedItem =
      newSelectOptions.find(
        (option) => option.value.toLowerCase() === inputValue.toLowerCase()
      ) || focusedItem;

    switch (event.key) {
      case "Enter":
        if (!isFilterDropdownOpen) {
          setIsFilterDropdownOpen((prev) => !prev);
        } else if (selectedItem && selectedItem.value !== "No results") {
          onSelect(selectedItem.value);
        }
        break;
      case "Tab":
      case "Escape":
        setIsFilterDropdownOpen(false);
        setActiveItem(null);
        break;
      case "ArrowUp":
      case "ArrowDown":
        event.preventDefault();
        handleMenuArrowKeys(event.key);
        break;
      default:
        break;
    }
  };

  const onTextInputChange = (
    _event: React.FormEvent<HTMLInputElement>,
    value: string
  ) => {
    setInputValue(value);
    if (!isFilterDropdownOpen) {
      setIsFilterDropdownOpen(true);
    }
  };

  const toggle = (toggleRef: React.Ref<MenuToggleElement>) => (
    <MenuToggle
      ref={toggleRef}
      variant="typeahead"
      onClick={() => {
        setIsFilterDropdownOpen(!isFilterDropdownOpen);
      }}
      isExpanded={isFilterDropdownOpen}
      isDisabled={isDisabled || !category.selectOptions.length}
      isFullWidth
    >
      <TextInputGroup isPlain>
        <TextInputGroupMain
          value={inputValue}
          onClick={() => {
            setIsFilterDropdownOpen(!isFilterDropdownOpen);
          }}
          onChange={onTextInputChange}
          onKeyDown={onInputKeyDown}
          id="typeahead-select-input"
          autoComplete="off"
          innerRef={textInputRef}
          placeholder={category.placeholderText}
          {...(activeItem && { "aria-activedescendant": activeItem })}
          role="combobox"
          isExpanded={isFilterDropdownOpen}
          aria-controls="select-typeahead-listbox"
        />

        <TextInputGroupUtilities>
          {!!inputValue && (
            <Button
              variant="plain"
              onClick={() => {
                setInputValue("");
                setFilterValue(null);
                textInputRef?.current?.focus();
              }}
              aria-label="Clear input value"
            >
              <TimesIcon aria-hidden />
            </Button>
          )}
          {filterValue?.length ? (
            <Badge isRead>{filterValue.length}</Badge>
          ) : null}
        </TextInputGroupUtilities>
      </TextInputGroup>
    </MenuToggle>
  );

  return (
    <ToolbarFilter
      id={`filter-control-${category.categoryKey}`}
      chips={chips}
      deleteChip={(_, chip) => onFilterClear(chip)}
      deleteChipGroup={onFilterClearAll}
      categoryName={category.title}
      showToolbarItem={showToolbarItem}
    >
      <Select
        className={css(isScrollable && "isScrollable")}
        aria-label={category.title}
        toggle={toggle}
        selected={filterValue}
        onOpenChange={(isOpen) => setIsFilterDropdownOpen(isOpen)}
        onSelect={(_, selection) => onSelect(selection as string)}
        isOpen={isFilterDropdownOpen}
      >
        <SelectList id="select-multi-typeahead-checkbox-listbox">
          {renderSelectOptions(() => true)}
        </SelectList>
      </Select>
    </ToolbarFilter>
  );
};

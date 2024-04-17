import * as React from "react";
import {
  Dropdown,
  DropdownItem,
  DropdownGroup,
  DropdownList,
  MenuToggle,
  SelectOptionProps,
  ToolbarToggleGroup,
  ToolbarItem,
} from "@patternfly/react-core";
import FilterIcon from "@patternfly/react-icons/dist/esm/icons/filter-icon";

import { FilterControl } from "./FilterControl";

export enum FilterType {
  select = "select",
  multiselect = "multiselect",
  search = "search",
  numsearch = "numsearch",
}

export type FilterValue = string[] | undefined | null;

export interface FilterSelectOptionProps {
  optionProps?: SelectOptionProps;
  value: string;
  label?: string;
  chipLabel?: string;
  groupLabel?: string;
}

export interface IBasicFilterCategory<
  /** The actual API objects we're filtering */
  TItem,
  TFilterCategoryKey extends string, // Unique identifiers for each filter category (inferred from key properties if possible)
> {
  /** For use in the filterValues state object. Must be unique per category. */
  categoryKey: TFilterCategoryKey;
  /** Title of the filter as displayed in the filter selection dropdown and filter chip groups. */
  title: string;
  /** Type of filter component to use to select the filter's content. */
  type: FilterType;
  /** Optional grouping to display this filter in the filter selection dropdown. */
  filterGroup?: string;
  /** For client side filtering, return the value of `TItem` the filter will be applied against. */
  getItemValue?: (item: TItem) => string | boolean; // For client-side filtering
  /** For server-side filtering, defaults to `key` if omitted. Does not need to be unique if the server supports joining repeated filters. */
  serverFilterField?: string;
  /**
   * For server-side filtering, return the search value for currently selected filter items.
   * Defaults to using the UI state's value if omitted.
   */
  getServerFilterValue?: (filterValue: FilterValue) => string[] | undefined;
}

export interface IMultiselectFilterCategory<
  TItem,
  TFilterCategoryKey extends string,
> extends IBasicFilterCategory<TItem, TFilterCategoryKey> {
  /** The full set of options to select from for this filter. */
  selectOptions:
    | FilterSelectOptionProps[]
    | Record<string, FilterSelectOptionProps[]>;
  /** Option search input field placeholder text. */
  placeholderText?: string;
  /** How to connect multiple selected options together. Defaults to "AND". */
  logicOperator?: "AND" | "OR";
}

export interface ISelectFilterCategory<TItem, TFilterCategoryKey extends string>
  extends IBasicFilterCategory<TItem, TFilterCategoryKey> {
  selectOptions: FilterSelectOptionProps[];
}

export interface ISearchFilterCategory<TItem, TFilterCategoryKey extends string>
  extends IBasicFilterCategory<TItem, TFilterCategoryKey> {
  placeholderText: string;
}

export type FilterCategory<TItem, TFilterCategoryKey extends string> =
  | IMultiselectFilterCategory<TItem, TFilterCategoryKey>
  | ISelectFilterCategory<TItem, TFilterCategoryKey>
  | ISearchFilterCategory<TItem, TFilterCategoryKey>;

export type IFilterValues<TFilterCategoryKey extends string> = Partial<
  Record<TFilterCategoryKey, FilterValue>
>;

export const getFilterLogicOperator = <
  TItem,
  TFilterCategoryKey extends string,
>(
  filterCategory?: FilterCategory<TItem, TFilterCategoryKey>,
  defaultOperator: "AND" | "OR" = "OR"
) =>
  (filterCategory &&
    (filterCategory as IMultiselectFilterCategory<TItem, TFilterCategoryKey>)
      .logicOperator) ||
  defaultOperator;

export interface IFilterToolbarProps<TItem, TFilterCategoryKey extends string> {
  filterCategories: FilterCategory<TItem, TFilterCategoryKey>[];
  filterValues: IFilterValues<TFilterCategoryKey>;
  setFilterValues: (values: IFilterValues<TFilterCategoryKey>) => void;
  beginToolbarItems?: JSX.Element;
  endToolbarItems?: JSX.Element;
  pagination?: JSX.Element;
  showFiltersSideBySide?: boolean;
  isDisabled?: boolean;
}

export const FilterToolbar = <TItem, TFilterCategoryKey extends string>({
  filterCategories,
  filterValues,
  setFilterValues,
  pagination,
  showFiltersSideBySide = false,
  isDisabled = false,
}: React.PropsWithChildren<
  IFilterToolbarProps<TItem, TFilterCategoryKey>
>): JSX.Element | null => {
  const [isCategoryDropdownOpen, setIsCategoryDropdownOpen] =
    React.useState(false);
  const [currentFilterCategoryKey, setCurrentFilterCategoryKey] =
    React.useState(filterCategories[0].categoryKey);

  const onCategorySelect = (
    category: FilterCategory<TItem, TFilterCategoryKey>
  ) => {
    setCurrentFilterCategoryKey(category.categoryKey);
    setIsCategoryDropdownOpen(false);
  };

  const setFilterValue = (
    category: FilterCategory<TItem, TFilterCategoryKey>,
    newValue: FilterValue
  ) => setFilterValues({ ...filterValues, [category.categoryKey]: newValue });

  const currentFilterCategory = filterCategories.find(
    (category) => category.categoryKey === currentFilterCategoryKey
  );

  const filterGroups = filterCategories.reduce(
    (groups, category) =>
      !category.filterGroup || groups.includes(category.filterGroup)
        ? groups
        : [...groups, category.filterGroup],
    [] as string[]
  );

  const renderDropdownItems = () => {
    if (filterGroups.length) {
      return filterGroups.map((filterGroup) => (
        <DropdownGroup label={filterGroup} key={filterGroup}>
          <DropdownList>
            {filterCategories
              .filter(
                (filterCategory) => filterCategory.filterGroup === filterGroup
              )
              .map((filterCategory) => {
                return (
                  <DropdownItem
                    id={`filter-category-${filterCategory.categoryKey}`}
                    key={filterCategory.categoryKey}
                    onClick={() => onCategorySelect(filterCategory)}
                  >
                    {filterCategory.title}
                  </DropdownItem>
                );
              })}
          </DropdownList>
        </DropdownGroup>
      ));
    } else {
      return filterCategories.map((category) => (
        <DropdownItem
          id={`filter-category-${category.categoryKey}`}
          key={category.categoryKey}
          onClick={() => onCategorySelect(category)}
        >
          {category.title}
        </DropdownItem>
      ));
    }
  };

  return (
    <>
      <ToolbarToggleGroup
        variant="filter-group"
        toggleIcon={<FilterIcon />}
        breakpoint="2xl"
        spaceItems={
          showFiltersSideBySide ? { default: "spaceItemsMd" } : undefined
        }
      >
        {!showFiltersSideBySide && (
          <ToolbarItem>
            <Dropdown
              toggle={(toggleRef) => (
                <MenuToggle
                  id="filtered-by"
                  ref={toggleRef}
                  onClick={() =>
                    setIsCategoryDropdownOpen(!isCategoryDropdownOpen)
                  }
                  isDisabled={isDisabled}
                >
                  <FilterIcon /> {currentFilterCategory?.title}
                </MenuToggle>
              )}
              isOpen={isCategoryDropdownOpen}
            >
              {renderDropdownItems()}
            </Dropdown>
          </ToolbarItem>
        )}

        {filterCategories.map((category) => (
          <FilterControl<TItem, TFilterCategoryKey>
            key={category.categoryKey}
            category={category}
            filterValue={filterValues[category.categoryKey]}
            setFilterValue={(newValue) => setFilterValue(category, newValue)}
            showToolbarItem={
              showFiltersSideBySide ||
              currentFilterCategory?.categoryKey === category.categoryKey
            }
            isDisabled={isDisabled}
          />
        ))}
      </ToolbarToggleGroup>
      {pagination ? (
        <ToolbarItem variant="pagination">{pagination}</ToolbarItem>
      ) : null}
    </>
  );
};

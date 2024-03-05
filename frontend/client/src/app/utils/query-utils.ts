import { useMemo } from "react";
import { UI_UNIQUE_ID } from "@app/Constants";
import { WithUiId } from "@app/api/models";

/**
 * Make a shallow copy of `data` and insert a new `UI_UNIQUE_ID` field in each element
 * with the output of the `generator` function.  This hook allows generating the needed
 * UI id field for any object that does not already have a unique id field so the object
 * can be used with our table selection handlers.
 *
 * @returns A shallow copy of `T` with an added `UI_UNIQUE_ID` field.
 */
export const useWithUiId = <T>(
  /** Source data to modify. */
  data: T[] | undefined,
  /** Generate the unique id for a specific `T`. */
  generator: (item: T) => string
): WithUiId<T>[] => {
  const result = useMemo(() => {
    if (!data || data.length === 0) {
      return [];
    }

    const dataWithUiId: WithUiId<T>[] = data.map((item) => ({
      ...item,
      [UI_UNIQUE_ID]: generator(item),
    }));

    return dataWithUiId;
  }, [data, generator]);

  return result;
};

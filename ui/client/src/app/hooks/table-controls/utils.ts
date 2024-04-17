import React from "react";

/**
 * Works around problems caused by event propagation when handling a clickable element that contains other clickable elements.
 * - Used internally by useTableControlProps for the active item feature, but is generic and could be used outside tables.
 * - When a click event happens within a row, checks if there is a clickable element in between the target node and the row element.
 *   (For example: checkboxes, buttons or links).
 * - Prevents triggering the row click behavior when inner clickable elements or their children are clicked.
 */
export const handlePropagatedRowClick = <
  E extends React.KeyboardEvent | React.MouseEvent,
>(
  event: E | undefined,
  onRowClick: (event: E) => void
) => {
  // This recursive parent check is necessary because the event target could be,
  // for example, the SVG icon inside a button rather than the button itself.
  const isClickableElementInTheWay = (element: Element): boolean => {
    if (["input", "button", "a"].includes(element.tagName.toLowerCase())) {
      return true;
    }
    if (
      !element.parentElement ||
      element.parentElement?.tagName.toLowerCase() === "tr"
    ) {
      return false;
    }
    return isClickableElementInTheWay(element.parentElement);
  };
  if (
    event?.target instanceof Element &&
    !isClickableElementInTheWay(event.target)
  ) {
    onRowClick(event);
  }
};

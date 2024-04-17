import * as React from "react";
import { FieldValues, Path } from "react-hook-form";
import { TextArea, TextAreaProps } from "@patternfly/react-core";
import { getValidatedFromErrors } from "@app/utils/utils";
import {
  HookFormPFGroupController,
  BaseHookFormPFGroupControllerProps,
  extractGroupControllerProps,
} from "./HookFormPFGroupController";

export type HookFormPFTextAreaProps<
  TFieldValues extends FieldValues,
  TName extends Path<TFieldValues>,
> = TextAreaProps & BaseHookFormPFGroupControllerProps<TFieldValues, TName>;

export const HookFormPFTextArea = <
  TFieldValues extends FieldValues = FieldValues,
  TName extends Path<TFieldValues> = Path<TFieldValues>,
>(
  props: HookFormPFTextAreaProps<TFieldValues, TName>
) => {
  const { extractedProps, remainingProps } = extractGroupControllerProps<
    TFieldValues,
    TName,
    HookFormPFTextAreaProps<TFieldValues, TName>
  >(props);
  const { fieldId, helperText, isRequired, errorsSuppressed } = extractedProps;
  return (
    <HookFormPFGroupController<TFieldValues, TName>
      {...extractedProps}
      renderInput={({
        field: { onChange, onBlur, value, name, ref },
        fieldState: { isDirty, error, isTouched },
      }) => (
        <TextArea
          ref={ref}
          name={name}
          id={fieldId}
          aria-describedby={helperText ? `${fieldId}-helper` : undefined}
          isRequired={isRequired}
          onChange={onChange}
          onBlur={onBlur}
          value={value}
          validated={
            errorsSuppressed
              ? "default"
              : getValidatedFromErrors(error, isDirty, isTouched)
          }
          {...remainingProps}
        />
      )}
    />
  );
};

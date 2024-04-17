import React, { useContext } from "react";

import { yupResolver } from "@hookform/resolvers/yup";
import { AxiosError } from "axios";
import { useForm } from "react-hook-form";
import { object, string } from "yup";

import {
  ActionGroup,
  Button,
  ButtonVariant,
  Form,
  FormSelectOption,
} from "@patternfly/react-core";

import { Importer } from "@app/api/models";
import {
  useCreateImporterMutation,
  useUpdateImporterMutation,
} from "@app/queries/importers";

import {
  HookFormPFSelect,
  HookFormPFTextInput,
} from "@app/components/HookFormPFFields";
import { NotificationsContext } from "@app/components/NotificationsContext";

export interface FormValues {
  name: string;
  type: "sbom" | "csaf";
  source: string;
  period: string;
}

export interface IImporterFormProps {
  importer?: Importer;
  onClose: () => void;
}

export const ImporterForm: React.FC<IImporterFormProps> = ({
  importer,
  onClose,
}) => {
  const { pushNotification } = useContext(NotificationsContext);

  const validationSchema = object().shape({
    name: string().trim().required().min(3).max(120),
    type: string().trim().required().min(3).max(250),
    source: string().trim().required().min(3).max(250),
    period: string().trim().required().min(3).max(250),
  });

  const {
    handleSubmit,
    formState: { isSubmitting, isValidating, isValid, isDirty },
    getValues,
    control,
  } = useForm<FormValues>({
    defaultValues: {
      name: importer?.name || "",
      type: importer?.configuration.sbom
        ? "sbom"
        : importer?.configuration.csaf
          ? "csaf"
          : "sbom",
      source:
        importer?.configuration.sbom?.source ||
        importer?.configuration.csaf?.source ||
        "",
      period:
        importer?.configuration.sbom?.period ||
        importer?.configuration.csaf?.period ||
        "60s",
    },
    resolver: yupResolver(validationSchema),
    mode: "onChange",
  });

  const onCreateSuccess = (_: Importer) =>
    pushNotification({
      title: "Importer created",
      variant: "success",
    });

  const onCreateError = (error: AxiosError) => {
    pushNotification({
      title: "Error while creating the Importer",
      variant: "danger",
    });
  };

  const { mutate: createSource } = useCreateImporterMutation(
    onCreateSuccess,
    onCreateError
  );

  const onUpdateSuccess = (_: Importer) =>
    pushNotification({
      title: "Importer updated",
      variant: "success",
    });

  const onUpdateError = (error: AxiosError) => {
    pushNotification({
      title: "Error while updating the Importer",
      variant: "danger",
    });
  };
  const { mutate: updateImporter } = useUpdateImporterMutation(
    onUpdateSuccess,
    onUpdateError
  );

  const onSubmit = (formValues: FormValues) => {
    const payload: Importer = {
      name: formValues.name.trim(),
      configuration: {
        [formValues.type]: {
          source: formValues.source.trim(),
          period: formValues.period.trim(),
        },
      },
    };

    if (importer) {
      updateImporter(payload);
    } else {
      createSource(payload);
    }
    onClose();
  };

  return (
    <Form onSubmit={handleSubmit(onSubmit)}>
      <HookFormPFSelect
        control={control}
        name="type"
        label="Type"
        fieldId="type"
        isRequired
      >
        {["sbom", "csaf"].map((option, index) => (
          <FormSelectOption key={index} value={option} label={option} />
        ))}
      </HookFormPFSelect>
      <HookFormPFTextInput
        control={control}
        name="name"
        label="Name"
        fieldId="name"
        isRequired
      />
      <HookFormPFTextInput
        control={control}
        name="source"
        label="Source"
        fieldId="source"
        isRequired
      />
      <HookFormPFTextInput
        control={control}
        name="period"
        label="Period"
        fieldId="period"
        isRequired
      />

      <ActionGroup>
        <Button
          type="submit"
          aria-label="submit"
          id="source-form-submit"
          variant={ButtonVariant.primary}
          isDisabled={!isValid || isSubmitting || isValidating || !isDirty}
        >
          {!importer ? "Create" : "Save"}
        </Button>
        <Button
          type="button"
          id="cancel"
          aria-label="cancel"
          variant={ButtonVariant.link}
          isDisabled={isSubmitting || isValidating}
          onClick={onClose}
        >
          Cancel
        </Button>
      </ActionGroup>
    </Form>
  );
};

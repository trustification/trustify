import React from "react";

import { LoadingWrapper } from "@app/components/LoadingWrapper";
import { useFetchAdvisorySourceById } from "@app/queries/advisories";
import { CodeEditor, Language } from "@patternfly/react-code-editor";

interface SourceProps {
  advisoryId: string;
}

export const Source: React.FC<SourceProps> = ({ advisoryId }) => {
  const { source, isFetching, fetchError } =
    useFetchAdvisorySourceById(advisoryId);

  return (
    <>
      <LoadingWrapper isFetching={isFetching} fetchError={fetchError}>
        <CodeEditor
          isDarkTheme
          isLineNumbersVisible
          isReadOnly
          isMinimapVisible
          // isLanguageLabelVisible
          code={source ?? ""}
          language={Language.json}
          height="685px"
        />
      </LoadingWrapper>
    </>
  );
};

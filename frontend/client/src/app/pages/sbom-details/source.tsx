import React from "react";

import { CodeEditor, Language } from "@patternfly/react-code-editor";

import { LoadingWrapper } from "@app/components/LoadingWrapper";
import { useFetchSBOMSourceById } from "@app/queries/sboms";

interface SourceProps {
  sbomId: string;
}

export const Source: React.FC<SourceProps> = ({ sbomId }) => {
  const { source, isFetching, fetchError } = useFetchSBOMSourceById(sbomId);

  return (
    <>
      <LoadingWrapper isFetching={isFetching} fetchError={fetchError}>
        <CodeEditor
          isDarkTheme
          isLineNumbersVisible
          isReadOnly
          isMinimapVisible
          code={source ?? ""}
          language={Language.json}
          height="700px"
        />
      </LoadingWrapper>
    </>
  );
};

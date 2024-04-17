import React from "react";

import { ImporterStatus } from "@app/api/models";
import { IconedStatus } from "@app/components/IconedStatus";

export interface ImporterStatusIconProps {
  state: ImporterStatus;
}

export type AnalysisState =
  | "Canceled"
  | "Scheduled"
  | "Completed"
  | "Failed"
  | "InProgress"
  | "NotStarted";

const importerStateToAnalyze: Map<ImporterStatus, AnalysisState> = new Map([
  ["waiting", "Scheduled"],
  ["running", "InProgress"],
]);

export const ImporterStatusIcon: React.FC<ImporterStatusIconProps> = ({
  state,
}) => {
  const getImporterStatus = (state: ImporterStatus): AnalysisState => {
    if (importerStateToAnalyze.has(state)) {
      const value = importerStateToAnalyze.get(state);
      if (value) return value;
    }
    return "NotStarted";
  };

  return <IconedStatus preset={getImporterStatus(state)} />;
};

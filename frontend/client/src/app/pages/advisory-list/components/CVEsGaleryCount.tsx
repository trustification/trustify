import React from "react";

import { CVEBase, Severity } from "@app/api/models";
import { CveGallery } from "@app/components/CveGallery";

type SeverityCount = { [key in Severity]: number };
const defaultSeverityCount: SeverityCount = {
  low: 0,
  moderate: 0,
  important: 0,
  critical: 0,
};

interface CVEsCountProps {
  cves: CVEBase[];
}

export const CVEGalleryCount: React.FC<CVEsCountProps> = ({ cves }) => {
  const severityCount = cves.reduce((prev, acc) => {
    return { ...prev, [acc.severity]: prev[acc.severity] + 1 };
  }, defaultSeverityCount);

  return <CveGallery severities={severityCount} />;
};

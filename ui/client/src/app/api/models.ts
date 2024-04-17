export type WithUiId<T> = T & { _ui_unique_id: string };

/** Mark an object as "New" therefore does not have an `id` field. */
export type New<T extends { id: number }> = Omit<T, "id">;

export interface HubFilter {
  field: string;
  operator?: "=" | "!=" | "~" | ">" | ">=" | "<" | "<=";
  value:
    | string
    | number
    | {
        list: (string | number)[];
        operator?: "AND" | "OR";
      };
}

export interface HubRequestParams {
  filters?: HubFilter[];
  sort?: {
    field: string;
    direction: "asc" | "desc";
  };
  page?: {
    pageNumber: number; // 1-indexed
    itemsPerPage: number;
  };
}

export interface HubPaginatedResult<T> {
  data: T[];
  total: number;
  params: HubRequestParams;
}

// Base

export interface CVEBase {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  date_discovered: string;
  date_released: string;
  date_reserved: string;
  date_updated: string;
}

export interface PackageBase {
  id: string;
  namespace: string;
  name: string;
  version: string;
  type: string;
  path?: string;
  qualifiers: { [key: string]: string };
}

export interface SBOMBase {
  id: string;
  type: "CycloneDX" | "SPDX";
  name: string;
  version: string;
  supplier: string;
  created_on: string;
}

export interface AdvisoryBase {
  id: string;
  severity: Severity;
  modified: string;
  title: string;
  metadata: {
    category: string;
    publisher: {
      name: string;
      namespace: string;
      contact_details: string;
      issuing_authority: string;
    };
    tracking: {
      status: string;
      initial_release_date: string;
      current_release_date: string;
    };
    references: {
      url: string;
      label?: string;
    }[];
    notes: string[];
  };
}

// Advisories

export type Severity = "low" | "moderate" | "important" | "critical";

export interface Advisory extends AdvisoryBase {
  cves: CVEBase[];
}

// CVE

export interface CVE extends CVEBase {
  related_sboms: SBOMBase[];
  related_advisories: AdvisoryBase[];
}

// Package

export interface Package extends PackageBase {
  related_cves: CVEBase[];
  related_sboms: SBOMBase[];
}

// SBOM

export interface SBOM extends SBOMBase {
  related_packages: {
    count: number;
  };
  related_cves: { [key in Severity]: number };
}

// Importer

export type ImporterStatus = "waiting" | "running";

export interface Importer {
  name: string;
  configuration: ImporterConfiguration;
  state?: ImporterStatus;
}

export interface ImporterConfiguration {
  sbom?: ImporterConfigurationValues;
  csaf?: ImporterConfigurationValues;
}

export interface ImporterConfigurationValues {
  period: string;
  source: string;
  disabled: boolean;
  v3Signatures: boolean;
  onlyPatterns: string[];
}

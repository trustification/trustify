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

// Advisories

export type Severity = "low" | "moderate" | "important" | "critical";

export interface Advisory {
  id: string;
  aggregated_severity: Severity;
  revision_date: string;
  vulnerabilities_count: { [key in Severity]: number };
  vulnerabilities: AdvisoryVulnerability[];
  metadata: {
    title: string;
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

export interface AdvisoryVulnerability {
  id: string;
  title: string;
  discovery_date: string;
  release_date: string;
  score: number;
  cwe: string;
}

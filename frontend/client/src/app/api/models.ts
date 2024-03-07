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
  severity: Severity;
  revision_date: string;
  vulnerabilities: { [key in Severity]: number };
  metadata: {
    title: string;
  };
}

export interface AdvisoryVulnerability {
  id: string;
  title: string;
  discovery_date: string;
  release_date: string;
  revision_date: string;
  score: number;
  cwe: number;
}

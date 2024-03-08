import { serializeRequestParamsForHub } from "@app/hooks/table-controls";
import axios from "axios";
import { Advisory, HubPaginatedResult, HubRequestParams } from "./models";

const HUB = "/hub";
export const ADVISORIES = HUB + "/advisories";

export const getHubPaginatedResult = <T>(
  url: string,
  params: HubRequestParams = {}
): Promise<HubPaginatedResult<T>> =>
  axios
    .get<T[]>(url, {
      params: serializeRequestParamsForHub(params),
    })
    .then(({ data, headers }) => ({
      data,
      total: headers["x-total"]
        ? parseInt(headers["x-total"], 10)
        : data.length,
      params,
    }));

export const getAdvisories = (params: HubRequestParams = {}) => {
  return getHubPaginatedResult<Advisory>(ADVISORIES, params);
};

export const getAdvisoryById = (id: number | string) => {
  return axios
    .get<Advisory>(`${ADVISORIES}/${id}`)
    .then((response) => response.data);
};

export const getAdvisorySourceById = (id: number | string) => {
  return axios
    .get<string>(`${ADVISORIES}/${id}/source`)
    .then((response) => response.data);
};

export const downloadAdvisoryById = (id: number | string) => {
  return axios.get<string>(`${ADVISORIES}/${id}/source`, {
    responseType: "arraybuffer",
    headers: { Accept: "text/plain", responseType: "blob" },
  });
};

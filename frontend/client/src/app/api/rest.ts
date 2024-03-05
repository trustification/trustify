import axios from "axios";
import { serializeRequestParamsForHub } from "@app/hooks/table-controls";
import { HubPaginatedResult, HubRequestParams } from "./models";

const HUB = "/hub";

interface ApiSearchResult<T> {
  total: number;
  result: T[];
}

export const getHubPaginatedResult = <T>(
  url: string,
  params: HubRequestParams = {}
): Promise<HubPaginatedResult<T>> =>
  axios
    .get<ApiSearchResult<T>>(url, {
      params: serializeRequestParamsForHub(params),
    })
    .then(({ data }) => ({
      data: data.result,
      total: data.total,
      params,
    }));

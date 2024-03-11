import { rest } from "msw";

import * as AppRest from "@app/api/rest";
import { CVE } from "@app/api/models";
import { mockAdvisoryArray } from "./advisories";
import { mockSBOMArray } from "./sboms";

export const mockCVEArray: CVE[] = mockAdvisoryArray.flatMap(({ cves }) => {
  return cves.map((cve) => {
    const result: CVE = {
      ...cve,
      related_advisories: mockAdvisoryArray,
      related_sboms: mockSBOMArray,
    };
    return result;
  });
});

export const handlers = [
  rest.get(AppRest.CVES, (req, res, ctx) => {
    return res(ctx.json(mockCVEArray));
  }),
  rest.get(`${AppRest.CVES}/:id`, (req, res, ctx) => {
    const { id } = req.params;
    const item = mockCVEArray.find((app) => app.id === id);
    if (item) {
      return res(ctx.json(item));
    } else {
      return res(ctx.status(404), ctx.json({ message: "CVE not found" }));
    }
  }),
  rest.get(`${AppRest.CVES}/:id/source`, (req, res, ctx) => {
    return res(
      ctx.json(
        "This is Mock data, but the real API should return the advisory JSON file"
      )
    );
  }),
];

export default handlers;

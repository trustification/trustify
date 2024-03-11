import { rest } from "msw";

import * as AppRest from "@app/api/rest";
import { mockPackageArray } from "./sboms";

export const handlers = [
  rest.get(AppRest.PACKAGES, (req, res, ctx) => {
    return res(ctx.json(mockPackageArray));
  }),
  rest.get(`${AppRest.PACKAGES}/:id`, (req, res, ctx) => {
    const { id } = req.params;
    const item = mockPackageArray.find((app) => app.id === id);
    if (item) {
      return res(ctx.json(item));
    } else {
      return res(ctx.status(404), ctx.json({ message: "Package not found" }));
    }
  }),
];

export default handlers;

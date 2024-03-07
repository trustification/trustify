import { rest } from "msw";

import * as AppRest from "@app/api/rest";
import { Advisory } from "@app/api/models";

export const mockProjectArray: Advisory[] = [
  {
    id: "Advisory-1",
    severity: "critical",
    revision_date: new Date().toString(),
    vulnerabilities: {
      critical: 2,
      important: 1,
      low: 3,
      moderate: 5,
    },
    metadata: {
      title: "Title 1",
    },
  },
  {
    id: "Advisory-2",
    severity: "moderate",
    revision_date: new Date().toString(),
    vulnerabilities: {
      critical: 2,
      important: 1,
      low: 3,
      moderate: 5,
    },
    metadata: {
      title: "Title 2",
    },
  },
];

export const handlers = [
  rest.get(AppRest.ADVISORIES, (req, res, ctx) => {
    return res(ctx.json(mockProjectArray));
  }),
  rest.get(`${AppRest.ADVISORIES}/:id`, (req, res, ctx) => {
    const { id } = req.params;
    const mockProject = mockProjectArray.find((app) => app.id === id);
    if (mockProject) {
      return res(ctx.json(mockProject));
    } else {
      return res(ctx.status(404), ctx.json({ message: "Advisory not found" }));
    }
  }),
  rest.get(`${AppRest.ADVISORIES}/:id/source`, (req, res, ctx) => {
    return res(ctx.json("{}"));
  }),
];

export default handlers;

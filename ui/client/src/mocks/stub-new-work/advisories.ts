import { rest } from "msw";

import * as AppRest from "@app/api/rest";
import { Advisory } from "@app/api/models";

export const mockAdvisoryArray: Advisory[] = [
  {
    id: "advisory-1",
    severity: "critical",
    modified: new Date().toString(),
    title: "Title 1",
    metadata: {
      category: "advisory.document.category",
      publisher: {
        name: "advisory.document.publisher.name",
        namespace: "advisory.document.publisher.namespace",
        contact_details: "advisory.document.publisher.contact_details",
        issuing_authority: "advisory.document.publisher.issuing_authority",
      },
      tracking: {
        status: "Final",
        initial_release_date: new Date().toString(),
        current_release_date: new Date().toString(),
      },
      references: [{ url: "http://somedomain.com" }],
      notes: [`# Title \n - List \n ## Subtitle \n _Italian_ \n > Note`],
    },
    cves: [
      {
        id: "cve1",
        title: "title1",
        description: "description1",
        severity: "critical",
        cwe: "cwe1",
        date_discovered: new Date().toString(),
        date_released: new Date().toString(),
        date_reserved: new Date().toString(),
        date_updated: new Date().toString(),
      },
      {
        id: "cve2",
        title: "title2",
        description: "description2",
        severity: "low",
        cwe: "cwe1",
        date_discovered: new Date().toString(),
        date_released: new Date().toString(),
        date_reserved: new Date().toString(),
        date_updated: new Date().toString(),
      },
    ],
  },
];

export const handlers = [
  rest.get(AppRest.ADVISORIES_SEARCH, (req, res, ctx) => {
    return res(
      ctx.json({ items: mockAdvisoryArray, total: mockAdvisoryArray.length })
    );
  }),
  rest.get(`${AppRest.ADVISORIES}/:id`, (req, res, ctx) => {
    const { id } = req.params;
    const item = mockAdvisoryArray.find((app) => app.id === id);
    if (item) {
      return res(ctx.json(item));
    } else {
      return res(ctx.status(404), ctx.json({ message: "Advisory not found" }));
    }
  }),
  rest.get(`${AppRest.ADVISORIES}/:id/source`, (req, res, ctx) => {
    return res(
      ctx.json(
        "This is Mock data, but the real API should return the advisory JSON file"
      )
    );
  }),
];

export default handlers;

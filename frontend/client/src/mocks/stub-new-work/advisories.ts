import { rest } from "msw";

import * as AppRest from "@app/api/rest";
import { Advisory } from "@app/api/models";

export const mockProjectArray: Advisory[] = [
  {
    id: "Advisory-1",
    aggregated_severity: "critical",
    revision_date: new Date().toString(),
    vulnerabilities_count: {
      critical: 2,
      important: 1,
      low: 3,
      moderate: 5,
    },
    metadata: {
      title: "Title 1",
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
    vulnerabilities: [
      {
        id: "cve1",
        title: "title1",
        discovery_date: new Date().toString(),
        release_date: new Date().toString(),
        severity: "critical",
        cwe: "cwe1",
      },
    ],
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
    return res(
      ctx.json(
        "This is Mock data, but the real API should return the advisory JSON file"
      )
    );
  }),
];

export default handlers;

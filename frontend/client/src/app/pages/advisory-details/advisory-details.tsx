import React from "react";
import ReactMarkdown from "react-markdown";
import { Link } from "react-router-dom";

import {
  Breadcrumb,
  BreadcrumbItem,
  PageSection,
  Stack,
  StackItem,
  TextContent,
} from "@patternfly/react-core";

import spacing from "@patternfly/react-styles/css/utilities/Spacing/spacing";

import DetailsPage from "@patternfly/react-component-groups/dist/dynamic/DetailsPage";
import DownloadIcon from "@patternfly/react-icons/dist/esm/icons/download-icon";

import { PathParam, useRouteParams } from "@app/Routes";
import { LoadingWrapper } from "@app/components/LoadingWrapper";
import { SeverityShieldAndText } from "@app/components/SeverityShieldAndText";
import { markdownPFComponents } from "@app/components/markdownPFComponents";

import { useDownload } from "@app/hooks/useDownload";
import { useFetchAdvisoryById } from "@app/queries/advisories";

import { Overview } from "./overview";
import { Source } from "./source";
import { Vulnerabilities } from "./vulnerabilities";

export const AdvisoryDetails: React.FC = () => {
  const advisoryId = useRouteParams(PathParam.ADVISORY_ID);
  const { advisory, isFetching, fetchError } = useFetchAdvisoryById(advisoryId);

  const { downloadAdvisory } = useDownload();

  return (
    <>
      <PageSection variant="light">
        <DetailsPage
          breadcrumbs={
            <Breadcrumb>
              <BreadcrumbItem key="advisories">
                <Link to="/advisories">Advisories</Link>
              </BreadcrumbItem>
              <BreadcrumbItem to="#" isActive>
                Advisory details
              </BreadcrumbItem>
            </Breadcrumb>
          }
          pageHeading={{
            title: advisoryId ?? "",
            label: advisory
              ? {
                  children: (
                    <SeverityShieldAndText
                      value={advisory.aggregated_severity}
                      showLabel
                    />
                  ),
                  isCompact: true,
                }
              : undefined,
          }}
          actionButtons={[
            {
              children: (
                <>
                  <DownloadIcon /> Download
                </>
              ),
              onClick: () => {
                if (advisoryId) {
                  downloadAdvisory(advisoryId);
                }
              },
              variant: "secondary",
            },
          ]}
          tabs={[
            {
              eventKey: "overview",
              title: "Overview",
              children: (
                <div className="pf-v5-u-m-md">
                  <LoadingWrapper
                    isFetching={isFetching}
                    fetchError={fetchError}
                  >
                    {advisory && <Overview advisory={advisory} />}
                  </LoadingWrapper>
                </div>
              ),
            },
            {
              eventKey: "notes",
              title: "Notes",
              children: (
                <div className="pf-v5-u-m-md">
                  <LoadingWrapper
                    isFetching={isFetching}
                    fetchError={fetchError}
                  >
                    <TextContent className={spacing.mbMd}>
                      <Stack hasGutter>
                        {advisory?.metadata.notes.map((e, index) => (
                          <StackItem key={index}>
                            <ReactMarkdown components={markdownPFComponents}>
                              {e}
                            </ReactMarkdown>
                          </StackItem>
                        ))}
                      </Stack>
                    </TextContent>
                  </LoadingWrapper>
                </div>
              ),
            },
            {
              eventKey: "vulnerabilities",
              title: "Vulnerabilities",
              children: (
                <div className="pf-v5-u-m-md">
                  <LoadingWrapper
                    isFetching={isFetching}
                    fetchError={fetchError}
                  >
                    <Vulnerabilities
                      vulnerabilities={advisory?.vulnerabilities || []}
                    />
                  </LoadingWrapper>
                </div>
              ),
            },
            {
              eventKey: "source",
              title: "Source",
              children: (
                <div className="pf-v5-u-m-md">
                  {advisoryId && <Source advisoryId={advisoryId} />}
                </div>
              ),
            },
          ]}
        />
      </PageSection>
    </>
  );
};
